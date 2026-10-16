#pragma once
#include "analyze.hpp"

// File bytes are not a process dump. Preserve virtual extent separately from
// stored bytes, and spend a bounded embedding budget on referenced pages first.
struct DataRegion {
    std::string name;u32 rva=0,flags=0;u64 size=0,fileSize=0,fileOffset=0;
    std::map<u64,std::vector<u8>> chunks;
};
struct DataImage {std::vector<DataRegion> regions;size_t embedded=0,budget=0;u64 fileBytes=0;};
inline DataImage collectStaticData(const PE&pe,const Analysis&a,size_t budget){
    DataImage d;d.budget=budget;
    u64 headerSize=pe.headersSize;
    for(const auto&s:pe.sections)if(s.rva<headerSize)headerSize=s.rva;
    if(headerSize)d.regions.push_back({"PE headers",0,0x40000000u,headerSize,std::min<u64>(headerSize,pe.data.size()),0,{}});
    for(const auto&s:pe.sections){u64 size=s.virtualSize?s.virtualSize:s.rawSize;
        if(size)d.regions.push_back({s.name,s.rva,s.flags,size,std::min<u64>(s.rawSize,size),s.raw,{}});
    }
    for(const auto&r:d.regions)d.fileBytes+=r.fileSize;
    auto addPage=[&](DataRegion&r,u64 page){
        if(page>=r.fileSize||d.embedded>=budget)return;
        size_t count=static_cast<size_t>(std::min<u64>({256,r.fileSize-page,budget-d.embedded}));
        if(r.chunks.contains(page))return;
        size_t off=static_cast<size_t>(r.fileOffset+page);pe.require(off,count);
        r.chunks[page]=std::vector<u8>(pe.data.begin()+off,pe.data.begin()+off+count);d.embedded+=count;
    };
    // Adjacent page helps previews when a referenced string crosses a page edge.
    for(const auto&[ip,i]:a.instructions){(void)ip;if(d.embedded>=budget)break;
        for(const auto&ref:i.dataRefs){auto target=pe.rvaOf(ref.va);if(!target)continue;
            for(auto&r:d.regions)if(*target>=r.rva&&u64(*target)-r.rva<r.size){
                u64 relative=u64(*target)-r.rva,page=relative/256*256;
                addPage(r,page);
                if(relative%256+std::max<u32>(ref.width,128)>256)addPage(r,page+256);
                break;
            }
        }
    }
    // Fill remaining budget: data sections first, then headers/code. Never
    // allocate virtual zero-fill bytes or claim omitted bytes are zero.
    for(int pass=0;pass<2;pass++)for(auto&r:d.regions){
        bool dataSection=r.rva!=0&&!(r.flags&0x20000000u);
        if(dataSection!=(pass==0))continue;
        for(u64 page=0;page<r.fileSize&&d.embedded<budget;page+=256)addPage(r,page);
    }
    return d;
}
