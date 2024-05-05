#pragma once
#include "../Helper/UnicornHelper.h"
#include "../Common/VmpCommon.h"

namespace ghidra
{
    class Funcdata;
}

class VmpNode
{
public:
    void append(VmpNode& other);
    void clear();
    size_t findRegContext(size_t eip,const std::string& regName);
    VmAddress readVmAddress(const std::string& reg_code);
public:
    std::vector<size_t> addrList;
    std::vector<reg_context> contextList;
};