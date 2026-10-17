#include "report.hpp"
#include <filesystem>
#include <iostream>
static u32 number(const std::string&s){size_t n=0;if(s.empty()||s[0]=='-')throw std::runtime_error("Invalid nonnegative number: "+s);u64 x=std::stoull(s,&n,0);if(n!=s.size()||x>UINT32_MAX)throw std::runtime_error("Invalid 32-bit number: "+s);return u32(x);}
static void usage(){std::cout<<"Usage: windows-exe-analyzer input.exe|input.dll [--html report.html] [--json report.json]\n"
    "       [--asm|--ir|--both] [--main-rva 0xRVA] [--name 0xRVA=label] [--data-name 0xRVA=label] [--limit N] [--data-limit BYTES]\n\n"
    "--main-rva is an analyst assertion, not automatic main detection.\n"
    "--ir displays conservative instruction notes, NOT recovered C or complete IR.\n"
    "--data-name labels a static data RVA, independently of code labels.\n"
    "--data-limit caps embedded original bytes: default 4194304, maximum 67108864.\n"
    "--no-unwind-seeds keeps metadata inspection but disables metadata-derived discovery.\n"
    "--no-tls-seeds inspects TLS metadata without adding callback roots.\n"
    "Read-only static analysis; input is never executed. VAs use preferred ImageBase.\n";}
int main(int argc,char**argv){try{
    if(argc<2){usage();return 2;}if(std::string(argv[1])=="--help"){usage();return 0;}
    std::string input=argv[1],htmlPath,jsonPath,mode="--asm";bool textExplicit=false,metadataDiscovery=true,tlsDiscovery=true;std::optional<u32> mainRva;std::map<u32,std::string> names,dataNames;size_t limit=100000,dataLimit=4*1024*1024;
    for(int k=2;k<argc;k++){std::string opt=argv[k];auto value=[&](){if(++k>=argc)throw std::runtime_error("Missing value for "+opt);return std::string(argv[k]);};
        if(opt=="--html")htmlPath=value();else if(opt=="--json")jsonPath=value();else if(opt=="--main-rva")mainRva=number(value());
        else if(opt=="--no-unwind-seeds")metadataDiscovery=false;
        else if(opt=="--no-tls-seeds")tlsDiscovery=false;
        else if(opt=="--limit"){limit=number(value());if(limit<1||limit>1000000)throw std::runtime_error("Limit must be 1..1000000");}
        else if(opt=="--data-limit"){dataLimit=number(value());if(dataLimit>64*1024*1024)throw std::runtime_error("Data limit must be 0..67108864 bytes");}
        else if(opt=="--name"||opt=="--data-name"){std::string s=value();auto eq=s.find('=');if(eq==s.npos)throw std::runtime_error("Name syntax: 0xRVA=label");std::string label=s.substr(eq+1);if(label.empty()||label.size()>160)throw std::runtime_error("Label must contain 1..160 bytes");(opt=="--name"?names:dataNames)[number(s.substr(0,eq))]=label;}
        else if(opt=="--asm"||opt=="--ir"||opt=="--both"){mode=opt;textExplicit=true;}else throw std::runtime_error("Unknown option: "+opt);
    }
    auto same=[](const std::string&a,const std::string&b){return !a.empty()&&!b.empty()&&std::filesystem::weakly_canonical(a)==std::filesystem::weakly_canonical(b);};
    if(same(input,htmlPath)||same(input,jsonPath)||same(htmlPath,jsonPath))throw std::runtime_error("Input and output paths must be distinct");
    PE pe(input);Analysis a=analyze(pe,limit,mainRva,names,metadataDiscovery,tlsDiscovery);std::string json=reportJson(pe,a,std::filesystem::path(input).filename().string(),dataLimit,dataNames);
    if(!htmlPath.empty()){writeHtml(htmlPath,json);std::cerr<<"HTML: "<<htmlPath<<'\n';}
    if(!jsonPath.empty()){std::ofstream f(jsonPath,std::ios::binary);if(!f||!(f<<json<<'\n'))throw std::runtime_error("Cannot write JSON");}
    std::cerr<<a.instructions.size()<<" instructions, "<<a.blocks.size()<<" blocks, "<<a.functions.size()<<" function candidates, "<<pe.imports.size()<<" imports.\n";
    for(const auto&w:a.warnings)std::cerr<<"Warning: "<<w<<'\n';
    if(textExplicit||(htmlPath.empty()&&jsonPath.empty()))for(const auto&[r,b]:a.blocks){std::cout<<"\n"<<b.name<<":  // RVA "<<hex(r)<<" | "<<b.evidence<<'\n';for(u32 ip:b.instructions){const auto&i=a.instructions.at(ip);
        if(mode!="--ir")std::cout<<"  "<<hex(pe.imageBase+ip)<<"  "<<i.mnemonic<<" "<<i.operands<<'\n';
        if(mode!="--asm")std::cout<<"    // "<<i.notes<<'\n';}}
    return a.instructions.empty()?1:0;
}catch(const std::exception&e){std::cerr<<"Error: "<<e.what()<<'\n';return 1;}}
