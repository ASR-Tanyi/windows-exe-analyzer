#pragma once
#include "analysis_types.hpp"
#include "operands.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using u8=std::uint8_t; using u16=std::uint16_t; using u32=std::uint32_t; using u64=std::uint64_t;
inline std::string hex(u64 x) {std::ostringstream s;s<<"0x"<<std::hex<<x;return s.str();}
inline std::string trim(std::string s) {auto a=s.find_first_not_of(" \t\r\n");if(a==s.npos)return {};return s.substr(a,s.find_last_not_of(" \t\r\n")-a+1);}
struct Section {std::string name;u32 rva=0,virtualSize=0,raw=0,rawSize=0,flags=0;bool executable()const{return flags&0x20000000u;}};
struct Import {u32 slot=0;std::string dll,name;};
struct Export {u32 rva=0;std::string name,forwarder;std::optional<u32> tableEntryRva;};
struct MemoryReference {
    u64 va=0; u32 width=0; unsigned operand=0;
    size_t textBegin=0,textEnd=0;
    std::int64_t displacement=0;
    std::string mode,access,evidence;
};
struct Instruction {
    u32 rva=0;u16 size=0;std::string bytes,mnemonic,operands,notes;
    bool call=false,jump=false,conditional=false,ret=false,stop=false;
    std::optional<u64> targetVA,memoryVA;
    std::vector<MemoryReference> dataRefs;
    wea::OperandDetails operandDetails;
};
struct Edge {u32 source=0,from=0;std::optional<u32> to;std::string kind,external,target;};
struct Function {
    u32 rva=0;std::string name,evidence;
    wea::EvidenceSet evidenceRecords;
    std::vector<wea::CodeRange> decodedRanges;
    std::vector<u32> metadataRecords; // Indices, not decoded coverage or source-function extents.
};
struct Block {
    u32 rva=0;std::vector<u32> instructions,owners;std::string name,role,summary,evidence;
    wea::EvidenceSet evidenceRecords;
    std::optional<wea::CodeRange> decodedRange;
};
struct Analysis {
    wea::DiagnosticLog diagnostics;
    bool tlsDiscovery = true;
    std::set<u32> tlsSeedRvas;
    bool metadataDiscovery = true;
    std::set<u32> metadataSeedRvas;
    std::map<u32,Instruction> instructions;std::map<u32,Function> functions;
    std::map<u32,Block> blocks;std::vector<Edge> edges;std::vector<std::string> warnings;
    std::optional<u32> mainRva;std::map<u32,std::string> names;bool truncated=false;
};
