#pragma once
#include "../Helper/UnicornHelper.h"

namespace ghidra
{
    class Funcdata;
}

class VmpNode
{
public:
    void append(VmpNode& other);
    void clear();
public:
    std::vector<size_t> addrList;
    std::vector<reg_context> contextList;
};