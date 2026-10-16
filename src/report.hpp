#pragma once
#include "analyze.hpp"
std::string reportJson(const PE&,const Analysis&,const std::string&filename,size_t dataLimit=4*1024*1024,
                       const std::map<u32,std::string>&dataNames={});
void writeHtml(const std::string&path,const std::string&json);
