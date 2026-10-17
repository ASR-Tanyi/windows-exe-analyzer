#include "string_scan.hpp"
#include <iostream>
#include <functional>
using namespace std::string_literals;
struct Section { std::uint32_t rva=0,raw=0,rawSize=0,virtualSize=0,flags=0x40000000; std::string name; };
struct Image {
    std::vector<std::uint8_t> data;
    std::vector<Section> sections;
    std::uint32_t imageSize=0x10000,headersSize=0;
    std::string moduleId="test";
    explicit Image(std::vector<std::uint8_t> bytes):data(std::move(bytes)) {
        sections.push_back({0x1000,0,static_cast<std::uint32_t>(data.size()),static_cast<std::uint32_t>(data.size()),0x40000000,"oddname"});
    }
};
static Image text(const std::string& s) {return Image({s.begin(),s.end()});}
static Image wide(const std::u16string& s) {std::vector<std::uint8_t>b;for(auto c:s){b.push_back(c&255);b.push_back(c>>8);}return Image(b);}
static const wea::StaticString* find(const wea::StringCatalog& c,std::uint32_t rva,const std::string& enc) {
    for (const auto& s:c.candidates) if(s.rva==rva&&s.encoding==enc)return &s;
    return nullptr;
}
int main(){int checks=0;
 auto check=[&](bool b,const char* why){++checks;if(!b)throw std::runtime_error(why);};
 auto a=text(std::string("Alpha\0Beta\0",11));auto c=wea::scanStaticStrings(a);
 check(find(c,0x1000,"ASCII")&&find(c,0x1000,"ASCII")->terminated,"ASCII nul");
 check(find(c,0x1006,"ASCII")&&find(c,0x1006,"ASCII")->byteLength==4,"separate run");
 check(find(c,0x1000,"ASCII")->section=="oddname","section name independent");
 auto w=wide(u"\u6d4b\u8bd5\u7a0b\u5e8f\U0001f680\0"s);
 c=wea::scanStaticStrings(w);auto p=find(c,0x1000,"UTF-16LE");
 check(p&&p->characters==5&&p->codeUnits==6&&p->byteLength==12,"non-Latin and surrogate counts");
 check(p&&p->preview.back()==0x1f680&&p->terminated,"surrogate preview");
 w.data.insert(w.data.begin(),0xff);++w.sections[0].rawSize;++w.sections[0].virtualSize;
 c=wea::scanStaticStrings(w);check(find(c,0x1001,"UTF-16LE")!=nullptr,"odd alignment");
 auto broken=wide(std::u16string(u"ABCD")+char16_t(0xd800)+u"WXYZ\0"s);c=wea::scanStaticStrings(broken);
 check(find(c,0x1000,"UTF-16LE")->endReason=="invalid_utf16","unpaired high rejected");
 check(find(c,0x100a,"UTF-16LE")!=nullptr,"resync following high");
 broken=wide(std::u16string(u"ABCD")+char16_t(0xdc00)+u"WXYZ\0"s);c=wea::scanStaticStrings(broken);
 check(find(c,0x1000,"UTF-16LE")->endReason=="invalid_utf16","unpaired low rejected");
 auto shortone=text("abc");check(wea::scanStaticStrings(shortone).candidates.empty(),"minimum characters");
 wea::StringOptions o;o.minCharacters=3;check(!wea::scanStaticStrings(shortone,o).candidates.empty(),"configured minimum");
 a=text("Alpha");c=wea::scanStaticStrings(a);check(!find(c,0x1000,"ASCII")->terminated,"range boundary is not nul");
 o={};o.scanLimit=4;c=wea::scanStaticStrings(a,o);check(c.partial&&find(c,0x1000,"ASCII")->endReason=="scan_limit","scan prefix");
 o.scanLimit=0;c=wea::scanStaticStrings(a,o);check(c.partial&&c.candidates.empty(),"zero scan limit");
 o={};o.candidateLimit=0;c=wea::scanStaticStrings(a,o);check(c.partial&&c.candidates.empty(),"zero candidates");
 o.candidateLimit=1;c=wea::scanStaticStrings(a,o);check(!c.partial&&c.candidates.size()==1,"exact candidate limit");
 a=text(std::string("Alpha\0Bravo\0",12));c=wea::scanStaticStrings(a,o);check(c.partial&&c.candidates.size()==1,"candidate overflow");
 a=text(std::string("Repeat\0Repeat\0",14));c=wea::scanStaticStrings(a);check(find(c,0x1000,"ASCII")&&find(c,0x1007,"ASCII"),"same text distinct address");
 a=text(std::string(300,'x')+std::string(1,0));c=wea::scanStaticStrings(a);p=find(c,0x1000,"ASCII");
 check(p->preview.size()==256&&p->previewTruncated&&p->characters==300&&p->terminated,"long preview full bounds");
 a=text("Alpha");a.sections[0].virtualSize=100;c=wea::scanStaticStrings(a);
 check(find(c,0x1000,"ASCII")->endReason=="range_end"&&c.readableBytes==5,"no invented zero-fill");
 a.sections[0].flags=0;c=wea::scanStaticStrings(a);check(c.candidates.empty(),"nonreadable section skipped");
 a.headersSize=5;c=wea::scanStaticStrings(a);check(find(c,0,"ASCII"),"headers scanned");
 a=text("AlphaHidden");a.sections[0].virtualSize=5;c=wea::scanStaticStrings(a);
 check(find(c,0x1000,"ASCII")->byteLength==5,"raw padding excluded");
 a=text("Alpha");a.imageSize=0x1004;c=wea::scanStaticStrings(a);check(find(c,0x1000,"ASCII")->byteLength==4,"image bounds");
 a=text("Alpha");a.sections[0].rva=0xfffffffau;a.imageSize=0xffffffffu;c=wea::scanStaticStrings(a);check(find(c,0xfffffffau,"ASCII"),"high unsigned RVA");
 a=text("Alpha");a.sections[0].rva=2;a.headersSize=5;c=wea::scanStaticStrings(a);check(c.partial&&c.readableBytes==7,"overlap not double counted");
 a=text("Alpha");o={};o.enabled=false;c=wea::scanStaticStrings(a,o);check(c.candidates.empty()&&!c.partial,"disabled");
 o={};o.minCharacters=0;bool threw=false;try{wea::scanStaticStrings(a,o);}catch(const std::invalid_argument&){threw=true;}check(threw,"invalid option");
 auto json=wea::stringJsonText(U"<script>\"\\\U0001f680");check(json.find('<')==json.npos&&json.find("\\ud83d\\ude80")!=json.npos,"JSON surrogate and script escaping");
 c=wea::scanStaticStrings(a);const auto j=wea::stringCatalogJson("mod",c);check(j.find("mod_str_a_1000")!=j.npos,"stable string ID");
 std::string report="{}";wea::appendStringCatalog(report,a);check(report.find("\"strings\":{")!=report.npos,"report extension");
 // Fixed scalar predicate handles malformed Unicode separately from text policy.
 check(!wea::stringTextScalar(0xd800)&&!wea::stringTextScalar(0x202e)&&wea::stringTextScalar(0x4e2d),"scalar policy");
 // Adjacent sections are explicit candidate boundaries, even when RVAs touch.
 a=text("ABCDWXYZ");a.sections={{0x1000,0,4,4,0x40000000,"one"},{0x1004,4,4,4,0x40000000,"two"}};
 c=wea::scanStaticStrings(a);check(find(c,0x1000,"ASCII")->byteLength==4&&find(c,0x1004,"ASCII"),"section boundaries");
 a=text("AAAA");a.sections[0].raw=20;check(wea::scanStaticStrings(a).candidates.empty(),"unbacked raw skipped");
 auto partialWide=wide(std::u16string(u"ABCD")+char16_t(0xd800));c=wea::scanStaticStrings(partialWide);
 check(find(c,0x1000,"UTF-16LE")->endReason=="incomplete_utf16","incomplete pair at end");
 a=text(std::string(100,'x'));o={};o.scanLimit=100;c=wea::scanStaticStrings(a,o);check(!c.partial,"exact byte limit complete");
 std::string repeated;for(unsigned k=0;k<4100;k++){repeated+=std::string(260,'A');repeated+=char(0);}
 a=text(repeated);a.imageSize=0x400000;c=wea::scanStaticStrings(a);
 check(c.partial&&c.previewScalars<=c.previewBudget&&std::find(c.reasons.begin(),c.reasons.end(),"preview_budget")!=c.reasons.end(),"global preview bound");
 std::cout<<"PASS: "<<checks<<" static-string native checks\n";
}
