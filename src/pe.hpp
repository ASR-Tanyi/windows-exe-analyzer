#pragma once
#include "model.hpp"
class PE {
public:
    std::vector<u8> data;std::vector<Section> sections;std::map<u32,Import> imports;
    std::vector<Export> exports;std::vector<std::string> warnings;
    bool is64=false,dll=false;u64 imageBase=0;u32 entryRva=0,headersSize=0,imageSize=0;
    std::string moduleId;std::vector<std::pair<u32,u32>> directories;
    explicit PE(const std::string& path) {
        std::ifstream f(path,std::ios::binary|std::ios::ate);
        if(!f)throw std::runtime_error("Cannot open input: "+path);
        auto n=f.tellg();if(n<64||n>256*1024*1024)throw std::runtime_error("Input must be 64 bytes to 256 MiB");
        data.resize(static_cast<size_t>(n));f.seekg(0);
        if(!f.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(n)))throw std::runtime_error("Input read failed");
        u64 hash=14695981039346656037ull;for(u8 b:data){hash^=b;hash*=1099511628211ull;}
        moduleId="m_"+hex(hash).substr(2);parse();
        try{parseImports();}catch(const std::exception&e){warnings.push_back(std::string("Import parsing incomplete: ")+e.what());}
        try{parseExports();}catch(const std::exception&e){warnings.push_back(std::string("Export parsing incomplete: ")+e.what());}
        if(directories.size()>13&&directories[13].first)warnings.push_back("Delay-import resolution is not implemented.");
        if(directories.size()>9&&directories[9].first)warnings.push_back("TLS callback discovery is not implemented; callbacks may run before the PE entry point.");
        if(directories.size()>14&&directories[14].first)warnings.push_back("CLR metadata is present. Managed IL is not decoded by this native-code analyzer.");
    }
    void require(size_t p,size_t n)const{if(p>data.size()||n>data.size()-p)throw std::runtime_error("Truncated/out-of-range PE data");}
    u16 rd16(size_t p)const{require(p,2);return u16(data[p])|u16(u16(data[p+1])<<8);}
    u32 rd32(size_t p)const{require(p,4);return u32(rd16(p))|(u32(rd16(p+2))<<16);}
    u64 rd64(size_t p)const{require(p,8);return u64(rd32(p))|(u64(rd32(p+4))<<32);}
    size_t available(u32 rva,bool exec=false)const{
        if(!exec&&rva<headersSize&&rva<data.size())return std::min<size_t>(headersSize-rva,data.size()-rva);
        for(const auto&s:sections){
            if((exec&&!s.executable())||rva<s.rva)continue;
            u64 delta=u64(rva)-s.rva,valid=s.virtualSize?std::min(s.rawSize,s.virtualSize):s.rawSize;
            u64 off=u64(s.raw)+delta;if(delta>=valid||off>=data.size())continue;
            return static_cast<size_t>(std::min<u64>(valid-delta,data.size()-off));
        }return 0;
    }
    size_t offset(u32 rva,size_t n=1,bool exec=false)const{
        if(available(rva,exec)<n)throw std::runtime_error("RVA not fully file-backed: "+hex(rva));
        if(!exec&&rva<headersSize)return rva;
        for(const auto&s:sections){if((exec&&!s.executable())||rva<s.rva)continue;
            u64 d=u64(rva)-s.rva,valid=s.virtualSize?std::min(s.rawSize,s.virtualSize):s.rawSize;
            if(d<valid&&u64(s.raw)+d<data.size())return static_cast<size_t>(u64(s.raw)+d);
        }throw std::runtime_error("Unmapped RVA");
    }
    u32 r32(u32 rva)const{return rd32(offset(rva,4));}
    std::string str(u32 rva)const{
        size_t count=std::min<size_t>(available(rva),4096),off=offset(rva);std::string s;
        for(size_t i=0;i<count;i++){if(!data[off+i])return s;s+=char(data[off+i]);}
        throw std::runtime_error("Unterminated/oversized PE string");
    }
    std::optional<u32> rvaOf(u64 va)const{if(va<imageBase||va-imageBase>UINT32_MAX)return {};return u32(va-imageBase);}
private:
    static u32 plus(u32 a,u64 b){if(u64(a)+b>UINT32_MAX)throw std::runtime_error("RVA overflow");return u32(u64(a)+b);}
    void parse(){
        if(rd16(0)!=0x5a4d)throw std::runtime_error("Missing MZ signature");
        size_t p=rd32(0x3c);require(p,24);if(rd32(p)!=0x4550)throw std::runtime_error("Missing PE signature");
        u16 machine=rd16(p+4),count=rd16(p+6),optSize=rd16(p+20);dll=(rd16(p+22)&0x2000)!=0;
        size_t o=p+24;require(o,optSize);if(optSize<96)throw std::runtime_error("Short optional header");
        u16 magic=rd16(o);is64=machine==0x8664&&magic==0x20b;
        if(!is64&&!(machine==0x14c&&magic==0x10b))throw std::runtime_error("Only native x86 PE32 / x64 PE32+ supported");
        size_t d=is64?112:96;if(optSize<d)throw std::runtime_error("Short optional header");
        entryRva=rd32(o+16);imageBase=is64?rd64(o+24):rd32(o+28);imageSize=rd32(o+56);headersSize=rd32(o+60);
        if(imageBase>UINT64_MAX-UINT32_MAX)throw std::runtime_error("Image address overflow");
        size_t n=rd32(o+(is64?108:92));if(n>(optSize-d)/8)throw std::runtime_error("Data directories exceed optional header");
        for(size_t i=0;i<std::min<size_t>(n,16);i++)directories.emplace_back(rd32(o+d+8*i),rd32(o+d+8*i+4));
        size_t sh=o+optSize;if(count>96)throw std::runtime_error("Too many sections");require(sh,size_t(count)*40);
        for(size_t i=0;i<count;i++){
            size_t b=sh+i*40;Section s;
            for(size_t j=0;j<8&&data[b+j];j++)s.name+=char(data[b+j]);
            s.virtualSize=rd32(b+8);s.rva=rd32(b+12);s.rawSize=rd32(b+16);s.raw=rd32(b+20);s.flags=rd32(b+36);
            if(s.rawSize)require(s.raw,s.rawSize);
            if(u64(s.rva)+std::max(s.rawSize,s.virtualSize)>u64(UINT32_MAX)+1)throw std::runtime_error("Section RVA overflow");
            for(const auto&t:sections){u64 e=u64(s.rva)+std::max(s.rawSize,s.virtualSize),te=u64(t.rva)+std::max(t.rawSize,t.virtualSize);
                if(s.rva<te&&t.rva<e)throw std::runtime_error("Overlapping sections are unsupported");}
            sections.push_back(s);
        }
    }
    void parseImports(){
        if(directories.size()<2||!directories[1].first)return;
        auto [rva,size]=directories[1];size_t count=std::min<size_t>(size/20,4096);
        for(size_t i=0;i<count;i++){
            size_t p=offset(plus(rva,i*20),20);u32 lookup=rd32(p),name=rd32(p+12),iat=rd32(p+16);
            if(!lookup&&!rd32(p+4)&&!rd32(p+8)&&!name&&!iat)return;
            if(!name||!iat)throw std::runtime_error("Malformed import descriptor");
            std::string dllName=str(name);if(!lookup)lookup=iat;
            size_t width=is64?8:4;bool terminated=false;
            for(size_t k=0;k<65536;k++){
                u32 q=plus(lookup,k*width),slot=plus(iat,k*width);size_t off=offset(q,width);
                u64 val=is64?rd64(off):rd32(off);if(!val){terminated=true;break;}
                u64 flag=is64?(1ull<<63):(1ull<<31);std::string symbol;
                if(val&flag)symbol="#"+std::to_string(val&0xffff);
                else{if(val>UINT32_MAX)throw std::runtime_error("Bound IAT cannot provide import names without lookup table");symbol=str(plus(u32(val),2));}
                imports[slot]={slot,dllName,symbol};
                if(imports.size()>100000)throw std::runtime_error("Import safety limit reached");
            }if(!terminated)throw std::runtime_error("Import thunk table limit reached");
        }throw std::runtime_error("Import descriptor table not terminated within directory size");
    }
    void parseExports(){
        if(directories.empty()||!directories[0].first)return;
        auto [rva,size]=directories[0];size_t p=offset(rva,40);
        u32 base=rd32(p+16),nf=rd32(p+20),nn=rd32(p+24),af=rd32(p+28),an=rd32(p+32),ao=rd32(p+36);
        if(nf>100000||nn>100000)throw std::runtime_error("Export safety limit reached");
        std::map<u32,std::string> names;
        for(u32 i=0;i<nn;i++){u16 ordinal=rd16(offset(plus(ao,u64(i)*2),2));if(ordinal>=nf)throw std::runtime_error("Invalid export ordinal");
            std::string n=str(r32(plus(an,u64(i)*4)));if(names.contains(ordinal))names[ordinal]+=" | "+n;else names[ordinal]=n;}
        for(u32 i=0;i<nf;i++){u32 target=r32(plus(af,u64(i)*4));if(!target)continue;
            Export e{target,names.contains(i)?names[i]:"ordinal_"+std::to_string(u64(base)+i),""};
            if(target>=rva&&u64(target)<u64(rva)+size)e.forwarder=str(target);
            exports.push_back(e);}
    }
};
