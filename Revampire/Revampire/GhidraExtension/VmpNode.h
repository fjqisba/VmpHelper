#pragma once
#include "../Helper/UnicornHelper.h"

namespace ghidra
{
    class Funcdata;
}

class VmpNode
{
public:
    std::vector<size_t> addrList;
    std::vector<reg_context> contextList;
private:
    ghidra::Funcdata* data;
};