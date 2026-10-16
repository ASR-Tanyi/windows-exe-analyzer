#include "unwind_info.hpp"
#include <iostream>

namespace {
struct Image {
    bool is64 = true;
    unsigned imageSize = 0x5000;
    std::string moduleId = "test";
    std::vector<unsigned char> data = std::vector<unsigned char>(imageSize);
    std::vector<std::pair<unsigned,unsigned>> directories = {{0,0},{0,0},{0,0},{0x2000,0}};
    std::size_t available(unsigned rva, bool executable=false) const {
        if (rva>=imageSize) return 0;
        if (executable) return rva>=0x1000 && rva<0x2000 ? 0x2000-rva : 0;
        return imageSize-rva;
    }
    std::size_t offset(unsigned rva,std::size_t size=1) const {
        if (available(rva)<size) throw std::out_of_range("Mock mapping");
        return rva;
    }
    void word(unsigned at,unsigned value) { for(unsigned k=0;k<4;++k)data.at(at+k)=value>>(k*8); }
    void record(unsigned index,unsigned begin,unsigned unwind) {
        word(0x2000+index*12,begin);word(0x2004+index*12,begin+16);word(0x2008+index*12,unwind);
        directories[3].second=(index+1)*12;
    }
    void chain(unsigned rva,unsigned parent) {
        data.at(rva)=0x21;word(rva+4,0x1100);word(rva+8,0x1110);word(rva+12,parent);
    }
};
unsigned checks=0;
void check(bool value) { if(!value)throw std::runtime_error("Unwind budget check #"+std::to_string(checks+1));++checks; }
wea::UnwindCatalog parse(Image& image,wea::DiagnosticLog& log,wea::UnwindLimits limits={}) {
    return wea::parseUnwindInfo(image,wea::parseExceptionDirectory(image,log),log,limits);
}
}
int main(){try{
    {
        Image i;for(unsigned n=0;n<3;++n){i.record(n,0x1010+n*32,0x3000+n*16);i.data[0x3000+n*16]=1;}
        wea::DiagnosticLog log;auto u=parse(i,log,{2,100,32});
        check(u.nodes.size()==2);check(u.partial);check(u.records[2].status=="budget_exhausted");
        check(log.counts().at(wea::DiagnosticCode::BudgetExhausted)==1);
    }
    {
        Image i;i.record(0,0x1010,0x3000);i.record(1,0x1030,0x3020);
        for(unsigned r:{0x3000,0x3020}){i.data[r]=1;i.data[r+1]=1;i.data[r+2]=1;i.data[r+4]=1;i.data[r+5]=0x32;}
        wea::DiagnosticLog log;auto u=parse(i,log,{100,1,32});
        check(u.slotsRead==1);check(u.records[0].eligible);check(u.records[1].status=="budget_exhausted");
        check(u.partial);check(u.nodes.at(0x3020).operations.empty());
    }
    {
        Image i;i.record(0,0x1010,0x3000);i.chain(0x3000,0x3020);i.chain(0x3020,0x3040);i.data[0x3040]=1;
        wea::DiagnosticLog log;auto u=parse(i,log,{100,100,2});
        check(u.nodes.size()==2);check(u.records[0].status=="budget_exhausted");check(!u.records[0].eligible);
        wea::DiagnosticLog second;auto complete=parse(i,second,{100,100,3});
        check(complete.records[0].eligible);check(complete.records[0].chainDepth==2);
    }
    {
        Image i;for(unsigned n=0;n<3;++n)i.record(n,0x1010+n*32,0x3000);
        i.data[0x3000]=1;i.data[0x3001]=1;i.data[0x3002]=1;i.data[0x3004]=1;i.data[0x3005]=0x32;
        wea::DiagnosticLog log;auto u=parse(i,log,{1,1,32});
        check(u.nodes.size()==1);check(u.slotsRead==1);check(!u.partial);
        check(std::all_of(u.records.begin(),u.records.end(),[](const auto& a){return a.eligible;}));
    }
    {
        Image i;i.record(0,0x1010,0x3000);i.data[0x3000]=3;i.data[0x3002]=255;
        wea::DiagnosticLog log;auto u=parse(i,log,{1,0,32});
        check(u.slotsRead==0);check(u.nodes.at(0x3000).operations.empty());check(u.records[0].status=="unsupported");
    }
    {
        Image i;i.record(0,0x1010,0x3000);i.chain(0x3000,0x3000);
        wea::DiagnosticLog log(0);auto u=parse(i,log);
        check(u.records[0].status=="invalid");check(log.total()>0);check(log.items().empty());check(log.omitted()==log.total());
    }
    std::cout<<"PASS: "<<checks<<" unwind limit/cache checks\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
