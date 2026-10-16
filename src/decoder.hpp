#pragma once
#include "pe.hpp"
#include <memory>
class Decoder {
public:
    explicit Decoder(bool x64);~Decoder();
    Decoder(const Decoder&)=delete;Decoder& operator=(const Decoder&)=delete;
    std::optional<Instruction> decode(const PE& pe,u32 rva);
    static const char* backend();
private:struct State;std::unique_ptr<State> s;
};
