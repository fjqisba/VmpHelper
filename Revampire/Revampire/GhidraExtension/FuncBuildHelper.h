#pragma once
#include "../Ghidra/funcdata.hh"

class PCodeBuildHelper
{
public:
    PCodeBuildHelper(ghidra::Funcdata& fd, ghidra::Address& addr) :data(fd), pc(addr) {};
    ~PCodeBuildHelper() {};
    ghidra::Varnode* CPUI_COPY(ghidra::Varnode* v1, size_t outSize);
    ghidra::Varnode* CPUI_POPCOUNT(ghidra::Varnode* v1, size_t outSize);
    ghidra::Varnode* CPUI_INT_AND(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_ADD(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_OR(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_SUB(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_XOR(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_LEFT(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_RIGHT(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_EQUAL(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_NOTEQUAL(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_INT_SLESS(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize);
    ghidra::Varnode* CPUI_BOOL_NEGATE(ghidra::Varnode* v1);
    ghidra::Varnode* CPUI_INT_NEGATE(ghidra::Varnode* v1, size_t outSize);
    ghidra::Varnode* CPUI_LOAD(ghidra::Varnode* v1, size_t outSize);
    void CPUI_STORE(ghidra::Varnode* dst, ghidra::Varnode* src);
private:
    ghidra::Funcdata& data;
    ghidra::Address& pc;
};

class FuncBuildHelper
{
public:
    //push 0x12345678
    static void BuildPushConst(ghidra::Funcdata& data, size_t addr, size_t val, size_t valSize);
    //push eax
    static void BuildPushRegister(ghidra::Funcdata& data, size_t addr, const ghidra::VarnodeData& regData);

	//andÁ½¸öunique
	static ghidra::Varnode* BuildAnd(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2, size_t opSize);
    static ghidra::Varnode* BuildAdd(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2, size_t opsize);
    static ghidra::Varnode* BuildShr(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2);
    static ghidra::Varnode* BuildShl(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2);

    static void BuildEflags(ghidra::Funcdata& data, size_t addr);
};