#include "FuncBuildHelper.h"

ghidra::Varnode* PCodeBuildHelper::CPUI_COPY(ghidra::Varnode* v1, size_t outSize)
{
    ghidra::PcodeOp* opCopy = data.newOp(1, pc);
    data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opCopy);
    data.opSetInput(opCopy, v1, 0);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_AND(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opAnd = data.newOp(2, pc);
    data.opSetOpcode(opAnd, ghidra::CPUI_INT_AND);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opAnd);
    data.opSetInput(opAnd, v1, 0);
    data.opSetInput(opAnd, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_ADD(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opAdd = data.newOp(2, pc);
    data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opAdd);
    data.opSetInput(opAdd, v1, 0);
    data.opSetInput(opAdd, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_OR(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opOr = data.newOp(2, pc);
    data.opSetOpcode(opOr, ghidra::CPUI_INT_OR);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opOr);
    data.opSetInput(opOr, v1, 0);
    data.opSetInput(opOr, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_SUB(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opSub = data.newOp(2, pc);
    data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opSub);
    data.opSetInput(opSub, v1, 0);
    data.opSetInput(opSub, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_XOR(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opXor = data.newOp(2, pc);
    data.opSetOpcode(opXor, ghidra::CPUI_INT_XOR);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opXor);
    data.opSetInput(opXor, v1, 0);
    data.opSetInput(opXor, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_LEFT(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opIntLeft = data.newOp(2, pc);
    data.opSetOpcode(opIntLeft, ghidra::CPUI_INT_LEFT);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opIntLeft);
    data.opSetInput(opIntLeft, v1, 0);
    data.opSetInput(opIntLeft, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_RIGHT(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opIntRight = data.newOp(2, pc);
    data.opSetOpcode(opIntRight, ghidra::CPUI_INT_RIGHT);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opIntRight);
    data.opSetInput(opIntRight, v1, 0);
    data.opSetInput(opIntRight, v2, 1);
    return uniqOut;
}

//outSize似乎只能是bool 1?

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_EQUAL(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opEqual = data.newOp(2, pc);
    data.opSetOpcode(opEqual, ghidra::CPUI_INT_EQUAL);
    ghidra::Varnode* uniqOut = data.newUniqueOut(0x1, opEqual);
    data.opSetInput(opEqual, v1, 0);
    data.opSetInput(opEqual, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_NOTEQUAL(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opNotEqual = data.newOp(2, pc);
    data.opSetOpcode(opNotEqual, ghidra::CPUI_INT_NOTEQUAL);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opNotEqual);
    data.opSetInput(opNotEqual, v1, 0);
    data.opSetInput(opNotEqual, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_POPCOUNT(ghidra::Varnode* v1, size_t outSize)
{
    ghidra::PcodeOp* opPopCount = data.newOp(1, pc);
    data.opSetOpcode(opPopCount, ghidra::CPUI_POPCOUNT);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opPopCount);
    data.opSetInput(opPopCount, v1, 0);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_SLESS(ghidra::Varnode* v1, ghidra::Varnode* v2, size_t outSize)
{
    ghidra::PcodeOp* opIntSless = data.newOp(2, pc);
    data.opSetOpcode(opIntSless, ghidra::CPUI_INT_SLESS);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opIntSless);
    data.opSetInput(opIntSless, v1, 0);
    data.opSetInput(opIntSless, v2, 1);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_BOOL_NEGATE(ghidra::Varnode* v1)
{
    ghidra::PcodeOp* opBoolNegate = data.newOp(1, pc);
    data.opSetOpcode(opBoolNegate, ghidra::CPUI_BOOL_NEGATE);
    ghidra::Varnode* uniqOut = data.newUniqueOut(0x1, opBoolNegate);
    data.opSetInput(opBoolNegate, v1, 0);
    return uniqOut;
}

//outSize可以是1、2、4

ghidra::Varnode* PCodeBuildHelper::CPUI_INT_NEGATE(ghidra::Varnode* v1, size_t outSize)
{
    ghidra::PcodeOp* opIntNegate = data.newOp(1, pc);
    data.opSetOpcode(opIntNegate, ghidra::CPUI_INT_NEGATE);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opIntNegate);
    data.opSetInput(opIntNegate, v1, 0);
    return uniqOut;
}

ghidra::Varnode* PCodeBuildHelper::CPUI_LOAD(ghidra::Varnode* v1, size_t outSize)
{
    ghidra::PcodeOp* opLoad = data.newOp(2, pc);
    data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
    ghidra::Varnode* uniqOut = data.newUniqueOut(outSize, opLoad);
    data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
    data.opSetInput(opLoad, v1, 1);
    return uniqOut;
}

void PCodeBuildHelper::CPUI_STORE(ghidra::Varnode* v1, ghidra::Varnode* v2)
{
    ghidra::PcodeOp* opStore = data.newOp(3, pc);
    data.opSetOpcode(opStore, ghidra::CPUI_STORE);
    data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
    data.opSetInput(opStore, v1, 1);
    data.opSetInput(opStore, v2, 2);
}
