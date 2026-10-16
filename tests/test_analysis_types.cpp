#include "analysis_types.hpp"
#include <iostream>
#include <limits>
#include <type_traits>

using namespace wea;
static unsigned checks=0;
static void check(bool condition,const char* message){
    if(!condition)throw std::runtime_error(message);
    ++checks;
}
template<class F> static void rejects(F f){
    bool threw=false;try{f();}catch(const std::exception&){threw=true;}
    check(threw,"Expected an invalid address/range to be rejected");
}
int main(){try{
    static_assert(!std::is_convertible_v<std::uint32_t,Rva>);
    static_assert(!std::is_convertible_v<Rva,FileOffset>);
    static_assert(!std::is_convertible_v<FileOffset,PreferredVa>);
    static_assert(!std::is_constructible_v<Address,std::uint64_t>);
    check(Rva(0).value()==0,"Zero RVA is representable");
    check(Rva(rvaEnd-1).value()==0xffffffffu,"Last RVA");
    rejects([]{(void)Rva(rvaEnd);});
    rejects([]{(void)Rva(std::numeric_limits<std::uint64_t>::max());});
    auto r=Address(Rva(16)),f=Address(FileOffset(16)),v=Address(PreferredVa(16));
    check(r!=f&&r!=v&&f!=v,"Coordinate systems must not compare equal");
    check(Address(PreferredVa(UINT64_MAX)).value()==UINT64_MAX,"Lossless VA storage");
    check(Location{"a",r}!=Location{"b",r},"Locations must be module qualified");
    CodeRange span(Rva(16),32);
    check(span.contains(Rva(16))&&span.contains(Rva(31)),"Range includes stored bytes");
    check(!span.contains(Rva(32))&&!span.contains(Rva(15)),"Exclusive end");
    check(span.size()==16,"Range byte count");
    CodeRange last(Rva(rvaEnd-1),rvaEnd);
    check(last.size()==1,"Exclusive endpoint may equal 2^32");
    rejects([]{(void)CodeRange(Rva(3),3);});
    rejects([]{(void)CodeRange(Rva(3),2);});
    rejects([]{(void)CodeRange(Rva(3),rvaEnd+1);});
    std::vector<CodeRange> ranges;
    appendDecodedRange(ranges,CodeRange(Rva(16),20));
    appendDecodedRange(ranges,CodeRange(Rva(20),24));
    appendDecodedRange(ranges,CodeRange(Rva(32),36));
    check(ranges.size()==2&&ranges[0].end()==24,"Only adjacency is coalesced");
    rejects([&]{appendDecodedRange(ranges,CodeRange(Rva(35),37));});
    rejects([&]{appendDecodedRange(ranges,CodeRange(Rva(1),2));});
    Evidence e{EvidenceOrigin::DecodedInstruction,"function_entry",Resolution::Encoded,
        EvidenceStatus::Candidate,"cfg.direct_call",1,Location{"m",Address(Rva(10))},"call",{}};
    EvidenceSet facts{e};facts.insert(e);
    check(facts.size()==1,"Duplicate evidence is deduplicated");
    e.source=Location{"m",Address(Rva(20))};facts.insert(e);
    check(facts.size()==2,"Distinct source instructions are retained");
    DiagnosticLog log(2);
    for(unsigned i=0;i<5;++i)log.add(DiagnosticCode::InvalidMetadata,"test","bad table");
    log.add(DiagnosticCode::UnresolvedSeed,"test","bad seed",Location{"m",r});
    check(log.total()==6&&log.items().size()==2&&log.omitted()==4,"Capped details, uncapped counts");
    check(log.counts().at(DiagnosticCode::InvalidMetadata)==5,"Per-code count");
    check(log.counts().at(DiagnosticCode::UnresolvedSeed)==1,"Second diagnostic code");
    auto copy=log;copy.add(DiagnosticCode::UnresolvedSeed,"test","another seed");
    check(log.total()==6&&copy.total()==7,"Diagnostic value semantics");
    DiagnosticLog zero(0);zero.add(DiagnosticCode::BudgetExhausted,"test","cap");
    check(zero.omitted()==1&&zero.items().empty(),"Zero-detail budget still counts");
    check(std::string(name(r.space()))=="rva","Address enum serialization");
    check(std::string(name(EvidenceOrigin::Analyst))=="analyst","Evidence enum serialization");
    check(std::string(name(Resolution::Supplied))=="supplied","Resolution enum serialization");
    check(std::string(name(EvidenceStatus::Assertion))=="assertion","Status enum serialization");
    check(std::string(name(DiagnosticCode::IgnoredAnnotation))=="ignored_annotation","Diagnostic enum serialization");
    rejects([]{(void)name(static_cast<AddressSpace>(99));});
    std::cout<<"PASS: "<<checks<<" analysis type checks\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
