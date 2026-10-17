#include "tls_directory.hpp"
#include <iostream>

// Independent bounded image adapter exercises mapping/counter limits without
// a decoder. End-to-end tests use real PE32/PE32+ bytes separately.
struct Image {
    struct Span {std::uint32_t rva; std::size_t raw, size; bool executable;};
    bool is64;
    std::uint64_t imageBase;
    std::uint32_t imageSize = 0x20000;
    std::string moduleId = "tls_test";
    std::vector<std::uint8_t> data = std::vector<std::uint8_t>(0x12000);
    std::vector<std::pair<std::uint32_t,std::uint32_t>> directories{16};
    std::vector<Span> spans{{0x1000,0,256,true},{0x2000,512,512,false},{0x3000,1024,65536,false}};
    explicit Image(bool wide=true):is64(wide),imageBase(wide?0x140000000ull:0x400000ull){
        directories[9]={0x2000,wide?40u:24u}; put(0x2000+3*width(),imageBase+0x3000,width());
    }
    unsigned width()const{return is64?8:4;}
    std::size_t available(std::uint32_t rva,bool code=false)const{
        for(const auto&s:spans)if(rva>=s.rva&&std::uint64_t(rva)-s.rva<s.size&&(!code||s.executable))return s.size-(rva-s.rva);
        return 0;
    }
    std::size_t offset(std::uint32_t rva,std::size_t count=1)const{
        for(const auto&s:spans)if(rva>=s.rva&&std::uint64_t(rva)-s.rva<s.size&&count<=s.size-(rva-s.rva))return s.raw+rva-s.rva;
        throw std::out_of_range("test image mapping");
    }
    void put(std::uint32_t at,std::uint64_t value,unsigned width){
        for(unsigned k=0;k<width;++k)data.at(offset(at+k))=std::uint8_t(value>>(8*k));
    }
    void callback(std::size_t k,std::uint64_t va){put(std::uint32_t(0x3000+k*width()),va,width());}
};
int main(){
    unsigned checks=0;
    auto check=[&](bool result){++checks;if(!result)throw std::runtime_error("TLS check #"+std::to_string(checks)+" failed");};
    auto parse=[](const Image&i){wea::DiagnosticLog log;return wea::parseTlsDirectory(i,log);};
    for(bool wide:{false,true}){
        Image i(wide);i.callback(0,i.imageBase+0x1010);i.callback(1,i.imageBase+0x1010);
        auto d=parse(i);check(d.status=="parsed"&&d.terminated);check(d.callbacks.size()==2);
        check(d.callbacks[1].duplicateOf==0);check(d.callbacks[0].eligible&&d.callbacks[1].eligible);
        check(d.terminatorRva==0x3000+2*i.width());check(d.callbacksFieldRva==0x2000+3*i.width());
        check(d.callbacks[0].targetRva==0x1010);check(d.pointerSize==i.width());
        i.callback(0,i.imageBase-1);d=parse(i);check(!d.callbacks[0].targetRva&&!d.callbacks[0].eligible);
        check(d.callbacks[1].eligible); // A bad sibling does not erase a valid encoded entry.
        i.callback(0,i.imageBase+0x2000);d=parse(i);check(!d.callbacks[0].executableFileBacked);
        i.callback(0,0);d=parse(i);check(d.callbacks.empty()&&d.terminated);
        i.put(0x2000+3*i.width(),0,i.width());d=parse(i);check(d.status=="no_callback_array"&&!d.terminated);
    }
    {Image i;i.directories[9]={0,0};check(parse(i).status=="absent");i.directories.resize(9);check(parse(i).status=="absent");}
    {Image i;i.directories[9].second=39;check(!parse(i).headerRead);i.directories[9]={0xfffffff0,40};check(parse(i).status=="malformed");}
    {Image i;i.spans[1].size=3;check(parse(i).partial);}
    {Image i;i.directories[9].second=513;auto d=parse(i);check(d.headerRead&&d.partial);}
    {Image i;i.put(0x2018,0x3000,8);auto d=parse(i);check(!d.arrayRva);}
    {Image i;i.callback(0,i.imageBase+0x1010);i.spans[2].size=8;auto d=parse(i);check(d.partial&&!d.terminated);check(d.callbacks.size()==1&&!d.callbacks[0].eligible);}
    {Image i;for(unsigned k=0;k<4096;++k)i.callback(k,i.imageBase+0x1010);auto d=parse(i);
     check(d.terminated&&!d.partial&&d.callbacks.size()==4096);check(d.callbacks.back().eligible);
     i.callback(4096,i.imageBase+0x1010);wea::DiagnosticLog log;d=wea::parseTlsDirectory(i,log);
     check(d.partial&&!d.terminated&&d.callbacks.size()==4096);check(!d.callbacks[0].eligible);
     check(log.counts().at(wea::DiagnosticCode::BudgetExhausted)==1);}
    {Image i;for(unsigned k=0;k<150;++k)i.callback(k,1);wea::DiagnosticLog log(2);auto d=wea::parseTlsDirectory(i,log);
     check(d.callbacks.size()==150);check(log.total()==150&&log.omitted()==148);}
    {Image i;i.spans[2].size=3;i.spans.push_back({0x3003,0x11000,32,false});
     i.callback(0,i.imageBase+0x1010);auto d=parse(i);check(d.terminated&&d.callbacks[0].eligible);}
    {Image i;i.spans[1].size=19;i.spans.push_back({0x2013,0x11100,64,false});
     i.put(0x2018,i.imageBase+0x3000,8);i.callback(0,i.imageBase+0x1010);
     check(parse(i).callbacks[0].eligible);}
    {Image i;i.imageBase=0xff00000000000000ull;i.put(0x2018,i.imageBase+0x3000,8);i.callback(0,i.imageBase+0x1010);
     check(parse(i).callbacks[0].targetVa==i.imageBase+0x1010);}
    {Image i(false);i.imageBase=0xffffd000;i.put(0x200c,0xfffffffc,4);
     i.spans.push_back({0x2ffc,0x11100,4,false});i.put(0x2ffc,0xffffe010,4);
     auto d=parse(i);check(d.callbacks.size()==1&&d.partial);check(!d.callbacks[0].eligible);}
    std::cout<<"PASS: "<<checks<<" TLS parser mapping/budget checks\n";
}
