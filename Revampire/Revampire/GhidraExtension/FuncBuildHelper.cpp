#include "FuncBuildHelper.h"

ghidra::Varnode* MergeEFlags(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* mergeNode, ghidra::VarnodeData& elf, size_t bitPos)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);

	//u1 = elf & #0x1:1
	ghidra::PcodeOp* opAnd = data.newOp(2, pc);
	data.opSetOpcode(opAnd, ghidra::CPUI_INT_AND);
	ghidra::Varnode* u1 = data.newUniqueOut(0x1, opAnd);
	data.opSetInput(opAnd, data.newVarnode(elf.size, elf.space, elf.offset), 0);
	data.opSetInput(opAnd, data.newConstant(0x1, 0x1), 1);

	//u2 = ZEXT14(u1)
	ghidra::PcodeOp* opZext = data.newOp(1, pc);
	data.opSetOpcode(opZext, ghidra::CPUI_INT_ZEXT);
	ghidra::Varnode* u2 = data.newUniqueOut(4, opZext);
	data.opSetInput(opZext, u1, 0);

	//u3 = #bitPos * u2
	ghidra::PcodeOp* opMult = data.newOp(2, pc);
	data.opSetOpcode(opMult, ghidra::CPUI_INT_MULT);
	ghidra::Varnode* u3 = data.newUniqueOut(4, opMult);
	data.opSetInput(opMult, data.newConstant(0x4, bitPos), 0);
	data.opSetInput(opMult, u2, 1);
	if (!mergeNode) {
		return u3;
	}
	ghidra::PcodeOp* opOr = data.newOp(2, pc);
	data.opSetOpcode(opOr, ghidra::CPUI_INT_OR);
	ghidra::Varnode* newMergeNode = data.newUniqueOut(4, opOr);
	data.opSetInput(opOr, mergeNode, 0);
	data.opSetInput(opOr, u3, 1);
	return newMergeNode;
}

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

void FuncBuildHelper::BuildPushRegister(ghidra::Funcdata& data, size_t addr, const ghidra::VarnodeData& regData)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");

	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Varnode* uniqReg = data.newUniqueOut(4, opCopy);
	data.opSetInput(opCopy, data.newVarnode(regData.size, regData.space, regData.offset), 0);

	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x4), 1);

	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	data.opSetInput(opStore, uniqReg, 2);

    return;
}

void FuncBuildHelper::BuildPushConst(ghidra::Funcdata& data, size_t addr, size_t val, size_t valSize)
{
    auto regESP = data.getArch()->translate->getRegister("ESP");

    //uniqReg = constant
    ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);
    ghidra::PcodeOp* opCopy = data.newOp(1, pc);
    data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
    ghidra::Varnode* uniqReg = data.newUniqueOut(valSize, opCopy);
    data.opSetInput(opCopy, data.newConstant(valSize, val), 0);

    //regESP = regESP - valSize
    ghidra::PcodeOp* opSub = data.newOp(2, pc);
    data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
    data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
    data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
    data.opSetInput(opSub, data.newConstant(4, valSize), 1);

    //*(ram,ESP(free)) = u0x00009a80:2(free)
    ghidra::PcodeOp* opStore = data.newOp(3, pc);
    data.opSetOpcode(opStore, ghidra::CPUI_STORE);
    data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
    data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
    data.opSetInput(opStore, uniqReg, 2);
}


void FuncBuildHelper::BuildEflags(ghidra::Funcdata & data, size_t addr)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);

	//auto regNT = data.getArch()->translate->getRegister("NT");
	auto regOF = data.getArch()->translate->getRegister("OF");
	//auto regDF = data.getArch()->translate->getRegister("DF");
	//auto regIF = data.getArch()->translate->getRegister("IF");
	auto regSF = data.getArch()->translate->getRegister("SF");
	auto regZF = data.getArch()->translate->getRegister("ZF");
	//auto regAF = data.getArch()->translate->getRegister("AF");
	auto regPF = data.getArch()->translate->getRegister("PF");
	auto regCF = data.getArch()->translate->getRegister("CF");

	ghidra::Varnode* mergeNode = nullptr;
	//mergeNode = MergeEFlags(data, addr, mergeNode, regNT, 0x4000);
	mergeNode = MergeEFlags(data, addr, mergeNode, regOF, 0x800);
	//mergeNode = MergeEFlags(data, addr, mergeNode, regDF, 0x400);
	//mergeNode = MergeEFlags(data, addr, mergeNode, regIF, 0x200);
	mergeNode = MergeEFlags(data, addr, mergeNode, regSF, 0x80);
	mergeNode = MergeEFlags(data, addr, mergeNode, regZF, 0x40);
	//mergeNode = MergeEFlags(data, addr, mergeNode, regAF, 0x10);
	mergeNode = MergeEFlags(data, addr, mergeNode, regPF, 0x4);
	mergeNode = MergeEFlags(data, addr, mergeNode, regCF, 0x1);

	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(4, regEFlags.getAddr(), opCopy);
	data.opSetInput(opCopy, mergeNode, 0);

	return;
}

ghidra::Varnode* FuncBuildHelper::BuildShl(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* uEax, ghidra::Varnode* uCL)
{
	auto regCF = data.getArch()->translate->getRegister("CF");
	auto regOF = data.getArch()->translate->getRegister("OF");
	auto regSF = data.getArch()->translate->getRegister("SF");
	auto regZF = data.getArch()->translate->getRegister("ZF");
	auto regPF = data.getArch()->translate->getRegister("PF");

	size_t opSize = uEax->getSize();
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);
	PCodeBuildHelper opBuilder(data, pc);

	//u0x0003b880:1(0x0040100f:e) = CL(free) & #0x1f:1
	ghidra::Varnode* u0x0003b880 = opBuilder.CPUI_INT_AND(uCL, data.newConstant(0x4, 0x1F), 0x1);
	//uResult = uEax(free) << u0x0003b880
	ghidra::Varnode* uResult = opBuilder.CPUI_INT_LEFT(uEax, u0x0003b880, opSize);
	//u0x00010100:1(0x0040100f:11) = u0x0003b880:1(free) != #0x0:1
	ghidra::Varnode* u0x00010100 = opBuilder.CPUI_INT_NOTEQUAL(u0x0003b880, data.newConstant(0x1, 0x0), 0x1);
	//u0x00010180:1(0x0040100f:12) = u0x0003b880:1(free) - #0x1:1
	ghidra::Varnode* u0x00010180 = opBuilder.CPUI_INT_SUB(u0x0003b880, data.newConstant(0x1, 0x1), 0x1);
	//u0x00010200(0x0040100f:13) = u0x0003b900(free) << u0x00010180:1(free)
	ghidra::Varnode* u0x00010200 = opBuilder.CPUI_INT_LEFT(uEax, u0x00010180, opSize);
	//u0x00010300:1(0x0040100f:14) = u0x00010200(free) < #0x0
	ghidra::Varnode* u0x00010300 = opBuilder.CPUI_INT_SLESS(u0x00010200, data.newConstant(opSize, 0x0), 0x1);
	//u0x00010380:1(0x0040100f:15) = ! u0x00010100:1(free)
	ghidra::Varnode* u0x00010380 = opBuilder.CPUI_BOOL_NEGATE(u0x00010100);
	//u0x00010400:1(0x0040100f:16) = u0x00010380:1(free) & CF(free)
	ghidra::Varnode* u0x00010400 = opBuilder.CPUI_INT_AND(u0x00010380, data.newVarnode(regCF.size, regCF.space, regCF.offset), 0x1);
	//u0x00010480:1(0x0040100f:17) = u0x00010100:1(free) & u0x00010300:1(free)
	ghidra::Varnode* u0x00010480 = opBuilder.CPUI_INT_AND(u0x00010100, u0x00010300, 0x1);

	//CF(0x0040100f:18) = u0x00010400:1(free) | u0x00010480:1(free)
	ghidra::PcodeOp* opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regCF.size, regCF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x00010400, 0);
	data.opSetInput(opIntOr, u0x00010480, 1);

	//u0x00010600:1(0x0040100f:19) = u0x0003b880:1(free) == #0x1:1
	ghidra::Varnode* u0x00010600 = opBuilder.CPUI_INT_EQUAL(u0x0003b880, data.newConstant(0x1, 0x1), 0x1);
	//u0x00010680:1(0x0040100f:1a) = EAX(free) < #0x0
	ghidra::Varnode* u0x00010680 = opBuilder.CPUI_INT_SLESS(uEax, data.newConstant(opSize, 0x0), 0x1);
	//u0x00010780:1(0x0040100f:1b) = CF(free) ^ u0x00010680:1(free)
	ghidra::Varnode* u0x00010780 = opBuilder.CPUI_INT_XOR(data.newVarnode(regCF.size, regCF.space, regCF.offset), u0x00010680, 0x1);
	//u0x00010800:1(0x0040100f:1c) = ! u0x00010600:1(free)
	ghidra::Varnode* u0x00010800 = opBuilder.CPUI_BOOL_NEGATE(u0x00010600);
	//u0x00010880:1(0x0040100f:1d) = u0x00010800:1(free) & OF(free)
	ghidra::Varnode* u0x00010880 = opBuilder.CPUI_INT_AND(u0x00010800, data.newVarnode(regOF.size, regOF.space, regOF.offset), 0x1);
	//u0x00010900:1(0x0040100f:1e) = u0x00010600:1(free) & u0x00010780:1(free)
	ghidra::Varnode* u0x00010900 = opBuilder.CPUI_INT_AND(u0x00010600, u0x00010780, 0x1);
	//OF(0x0040100f:1f) = u0x00010880:1(free) | u0x00010900:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regOF.size, regOF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x00010880, 0);
	data.opSetInput(opIntOr, u0x00010900, 1);


	//开始计算SF
	//u0x0000df80:1(0x0040100f:20) = u0x0003b880:1(free) != #0x0:1
	ghidra::Varnode* u0x0000df80 = opBuilder.CPUI_INT_NOTEQUAL(u0x0003b880, data.newConstant(0x1, 0x0), 0x1);
	//u0x0000e080:1(0x0040100f:21) = uResult < #0x0
	ghidra::Varnode* u0x0000e080 = opBuilder.CPUI_INT_SLESS(uResult, data.newConstant(opSize, 0x0), 0x1);
	//u0x0000e100:1(0x0040100f:22) = ! u0x0000df80:1(free)
	ghidra::Varnode* u0x0000e100 = opBuilder.CPUI_BOOL_NEGATE(u0x0000df80);
	//u0x0000e180:1(0x0040100f:23) = u0x0000e100:1(free) & SF(free)
	ghidra::Varnode* u0x0000e180 = opBuilder.CPUI_INT_AND(u0x0000e100, data.newVarnode(regSF.size, regSF.space, regSF.offset), 0x1);
	//u0x0000e200:1(0x0040100f:24) = u0x0000df80:1(free) & u0x0000e080:1(free)
	ghidra::Varnode* u0x0000e200 = opBuilder.CPUI_INT_AND(u0x0000df80, u0x0000e080, 0x1);
	//SF(0x0040100f:25) = u0x0000e180:1(free) | u0x0000e200:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regSF.size, regSF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x0000e180, 0);
	data.opSetInput(opIntOr, u0x0000e200, 1);

	//开始计算ZF
	//u0x0000e380:1(0x0040100f:26) = uResult == #0x0
	ghidra::Varnode* u0x0000e380 = opBuilder.CPUI_INT_EQUAL(uResult, data.newConstant(opSize, 0x0), 0x1);
	//u0x0000e400:1(0x0040100f:27) = ! u0x0000df80:1(free)
	ghidra::Varnode* u0x0000e400 = opBuilder.CPUI_BOOL_NEGATE(u0x0000df80);
	//u0x0000e480:1(0x0040100f:28) = u0x0000e400:1(free) & ZF(free)
	ghidra::Varnode* u0x0000e480 = opBuilder.CPUI_INT_AND(u0x0000e400, data.newVarnode(regZF.size, regZF.space, regZF.offset), 0x1);
	//u0x0000e500:1(0x0040100f:29) = u0x0000df80:1(free) & u0x0000e380:1(free)
	ghidra::Varnode* u0x0000e500 = opBuilder.CPUI_INT_AND(u0x0000df80, u0x0000e380, 0x1);
	//ZF(0x0040100f:2a) = u0x0000e480:1(free) | u0x0000e500:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regZF.size, regZF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x0000e480, 0);
	data.opSetInput(opIntOr, u0x0000e500, 1);

	//开始计算PF
	//u0x0000e600(0x0040100f:2b) = EAX(free) & #0xff
	ghidra::Varnode* u0x0000e600 = opBuilder.CPUI_INT_AND(uResult, data.newConstant(opSize, 0xFF), 0x4);
	//u0x0000e680:1(0x0040100f:2c) = POPCOUNT(u0x0000e600(free))
	ghidra::Varnode* u0x0000e680 = opBuilder.CPUI_POPCOUNT(u0x0000e600, 0x1);
	//u0x0000e700:1(0x0040100f:2d) = u0x0000e680:1(free) & #0x1:1
	ghidra::Varnode* u0x0000e700 = opBuilder.CPUI_INT_AND(u0x0000e680, data.newConstant(0x1, 0x1), 0x1);
	//u0x0000e800:1(0x0040100f:2e) = u0x0000e700:1(free) == #0x0:1
	ghidra::Varnode* u0x0000e800 = opBuilder.CPUI_INT_EQUAL(u0x0000e700, data.newConstant(0x1, 0x0), 0x1);
	//u0x0000e880:1(0x0040100f:2f) = ! u0x0000df80:1(free)
	ghidra::Varnode* u0x0000e880 = opBuilder.CPUI_BOOL_NEGATE(u0x0000df80);
	//u0x0000e900:1(0x0040100f:30) = u0x0000e880:1(free) & PF(free)
	ghidra::Varnode* u0x0000e900 = opBuilder.CPUI_INT_AND(u0x0000e880, data.newVarnode(regPF.size, regPF.space, regPF.offset), 0x1);
	//u0x0000e980:1(0x0040100f:31) = u0x0000df80:1(free) & u0x0000e800:1(free)
	ghidra::Varnode* u0x0000e980 = opBuilder.CPUI_INT_AND(u0x0000df80, u0x0000e800, 0x1);
	//PF(0x0040100f:32) = u0x0000e900:1(free) | u0x0000e980:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regPF.size, regPF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x0000e900, 0);
	data.opSetInput(opIntOr, u0x0000e980, 1);

	return uResult;
}

ghidra::Varnode* FuncBuildHelper::BuildShr(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* uEax, ghidra::Varnode* uCL)
{
	auto regCF = data.getArch()->translate->getRegister("CF");
	auto regOF = data.getArch()->translate->getRegister("OF");
	auto regSF = data.getArch()->translate->getRegister("SF");
	auto regZF = data.getArch()->translate->getRegister("ZF");
	auto regPF = data.getArch()->translate->getRegister("PF");

	size_t opSize = uEax->getSize();

	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);
	PCodeBuildHelper opBuilder(data, pc);
	//u0x0003e480 = uCL & #0x1f:1
	ghidra::Varnode* u0x0003e480 = opBuilder.CPUI_INT_AND(uCL, data.newConstant(0x1, 0x1F), 0x1);
	//uResult = uEax(free) >> u0x0003e480
	ghidra::Varnode* uResult = opBuilder.CPUI_INT_RIGHT(uEax, u0x0003e480, opSize);
	//u0x00011200 = u0x0003e480 != #0x0:1
	ghidra::Varnode* u0x00011200 = opBuilder.CPUI_INT_NOTEQUAL(u0x0003e480, data.newConstant(0x1, 0x0), 0x1);
	//u0x00011280 = u0x0003e480 - #0x1:1
	ghidra::Varnode* u0x00011280 = opBuilder.CPUI_INT_SUB(u0x0003e480, data.newConstant(0x1, 0x1), 0x1);
	//u0x00011300 = uEax >> u0x00011280
	ghidra::Varnode* u0x00011300 = opBuilder.CPUI_INT_RIGHT(uEax, u0x00011280, opSize);
	//u0x00011380 = u0x00011300 & #0x1
	ghidra::Varnode* u0x00011380 = opBuilder.CPUI_INT_AND(u0x00011300, data.newConstant(opSize, 0x1), opSize);
	//u0x00011480 = u0x00011380 != #0x0
	ghidra::Varnode* u0x00011480 = opBuilder.CPUI_INT_NOTEQUAL(u0x00011380, data.newConstant(opSize, 0x0), 0x1);
	//u0x00011500 = ! u0x00011200
	ghidra::Varnode* u0x00011500 = opBuilder.CPUI_BOOL_NEGATE(u0x00011200);

	//u0x00011580  = u0x00011500:1 & CF(free)
	ghidra::Varnode* u0x00011580 = opBuilder.CPUI_INT_AND(u0x00011500, data.newVarnode(regCF.size, regCF.space, regCF.offset), 0x1);
	//u0x00011600 = u0x00011200 & u0x00011480
	ghidra::Varnode* u0x00011600 = opBuilder.CPUI_INT_AND(u0x00011200, u0x00011480, 0x1);

	//CF = u0x00011580:1(free) | u0x00011600:1(free)
	ghidra::PcodeOp* opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regCF.size, regCF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x00011580, 0);
	data.opSetInput(opIntOr, u0x00011600, 1);

	//u0x00011780:1(0x0040100f:1a) = u0x0003e480:1(free) == #0x1:1
	ghidra::Varnode* u0x00011780 = opBuilder.CPUI_INT_EQUAL(u0x0003e480, data.newConstant(0x1, 0x1), 0x1);
	//u0x00011880:1(0x0040100f:1b) = uEax(free) < #0x0
	ghidra::Varnode* u0x00011880 = opBuilder.CPUI_INT_SLESS(uEax, data.newConstant(opSize, 0x0), 0x1);
	//u0x00011900:1(0x0040100f:1c) = ! u0x00011780:1(free)
	ghidra::Varnode* u0x00011900 = opBuilder.CPUI_BOOL_NEGATE(u0x00011780);
	//u0x00011980:1(0x0040100f:1d) = u0x00011900:1(free) & OF(free)
	ghidra::Varnode* u0x00011980 = opBuilder.CPUI_INT_AND(u0x00011900, data.newVarnode(regOF.size, regOF.space, regOF.offset), 0x1);
	//u0x00011a00:1(0x0040100f:1e) = u0x00011780:1(free) & u0x00011880:1(free)
	ghidra::Varnode* u0x00011a00 = opBuilder.CPUI_INT_AND(u0x00011780, u0x00011880, 0x1);
	//OF(0x0040100f:1f) = u0x00011980:1(free) | u0x00011a00:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regOF.size, regOF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x00011980, 0);
	data.opSetInput(opIntOr, u0x00011a00, 1);

	//u0x0000df80:1(0x0040100f:20) = u0x0003e480:1(free) != #0x0:1
	ghidra::Varnode* u0x0000df80 = opBuilder.CPUI_INT_NOTEQUAL(u0x0003e480, data.newConstant(0x1, 0x0), 0x1);

	//u0x0000e080:1(0x0040100f:21) = uResult < #0x0
	ghidra::Varnode* u0x0000e080 = opBuilder.CPUI_INT_SLESS(uResult, data.newConstant(opSize, 0x0), 0x1);

	//u0x0000e100:1(0x0040100f:22) = ! u0x0000df80:1(free)
	ghidra::Varnode* u0x0000e100 = opBuilder.CPUI_BOOL_NEGATE(u0x0000df80);

	//u0x0000e180:1(0x0040100f:23) = u0x0000e100:1(free) & SF(free)
	ghidra::Varnode* u0x0000e180 = opBuilder.CPUI_INT_AND(u0x0000e100, data.newVarnode(regSF.size, regSF.space, regSF.offset), 0x1);

	//u0x0000e200:1(0x0040100f:24) = u0x0000df80:1(free) & u0x0000e080:1(free)
	ghidra::Varnode* u0x0000e200 = opBuilder.CPUI_INT_AND(u0x0000df80, u0x0000e080, 0x1);

	//SF(0x0040100f:25) = u0x0000e180:1(free) | u0x0000e200:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regSF.size, regSF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x0000e180, 0);
	data.opSetInput(opIntOr, u0x0000e200, 1);

	//u0x0000e380:1(0x0040100f:26) = uResult == #0x0
	ghidra::Varnode* u0x0000e380 = opBuilder.CPUI_INT_EQUAL(uResult, data.newConstant(opSize, 0x0), 0x1);

	//u0x0000e400:1(0x0040100f:27) = ! u0x0000df80:1(free)
	ghidra::Varnode* u0x0000e400 = opBuilder.CPUI_BOOL_NEGATE(u0x0000df80);

	//u0x0000e480:1(0x0040100f:28) = u0x0000e400:1(free) & ZF(free)
	ghidra::Varnode* u0x0000e480 = opBuilder.CPUI_INT_AND(u0x0000e400, data.newVarnode(regZF.size, regZF.space, regZF.offset), 0x1);

	//u0x0000e500:1(0x0040100f:29) = u0x0000df80:1(free) & u0x0000e380:1(free)
	ghidra::Varnode* u0x0000e500 = opBuilder.CPUI_INT_AND(u0x0000df80, u0x0000e380, 0x1);

	//ZF(0x0040100f:2a) = u0x0000e480:1(free) | u0x0000e500:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regZF.size, regZF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x0000e480, 0);
	data.opSetInput(opIntOr, u0x0000e500, 1);

	//u0x0000e600(0x0040100f:2b) = EAX(free) & #0xff
	ghidra::Varnode* u0x0000e600 = opBuilder.CPUI_INT_AND(uResult, data.newConstant(opSize, 0xFF), opSize);

	//u0x0000e680:1(0x0040100f:2c) = POPCOUNT(u0x0000e600(free))
	ghidra::Varnode* u0x0000e680 = opBuilder.CPUI_POPCOUNT(u0x0000e600, 0x1);

	//u0x0000e700:1(0x0040100f:2d) = u0x0000e680:1(free) & #0x1:1
	ghidra::Varnode* u0x0000e700 = opBuilder.CPUI_INT_AND(u0x0000e680, data.newConstant(0x1, 0x1), 0x1);

	//u0x0000e800:1(0x0040100f:2e) = u0x0000e700:1(free) == #0x0:1
	ghidra::Varnode* u0x0000e800 = opBuilder.CPUI_INT_EQUAL(u0x0000e700, data.newConstant(0x1, 0x0), 0x1);

	//u0x0000e880:1(0x0040100f:2f) = ! u0x0000df80:1(free)
	ghidra::Varnode* u0x0000e880 = opBuilder.CPUI_BOOL_NEGATE(u0x0000df80);

	//u0x0000e900:1(0x0040100f:30) = u0x0000e880:1(free) & PF(free)
	ghidra::Varnode* u0x0000e900 = opBuilder.CPUI_INT_AND(u0x0000e880, data.newVarnode(regPF.size, regPF.space, regPF.offset), 0x1);

	//u0x0000e980:1(0x0040100f:31) = u0x0000df80:1(free) & u0x0000e800:1(free)
	ghidra::Varnode* u0x0000e980 = opBuilder.CPUI_INT_AND(u0x0000df80, u0x0000e800, 0x1);

	//PF(0x0040100f:32) = u0x0000e900:1(free) | u0x0000e980:1(free)
	opIntOr = data.newOp(2, pc);
	data.opSetOpcode(opIntOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regPF.size, regPF.getAddr(), opIntOr);
	data.opSetInput(opIntOr, u0x0000e900, 0);
	data.opSetInput(opIntOr, u0x0000e980, 1);

	return uResult;
}

ghidra::Varnode* FuncBuildHelper::BuildOr(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2, size_t opSize)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);
	PCodeBuildHelper opBuilder(data, pc);

	//CF = #0x0:1
	auto regCF = data.getArch()->translate->getRegister("CF");
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regCF.size, regCF.getAddr(), opCopy);
	data.opSetInput(opCopy, data.newConstant(0x1, 0x0), 0);

	//OF = #0x0:1
	auto regOF = data.getArch()->translate->getRegister("OF");
	opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regOF.size, regOF.getAddr(), opCopy);
	data.opSetInput(opCopy, data.newConstant(0x1, 0x0), 0);

	//uResult = v1 | v2
	ghidra::Varnode* uResult = opBuilder.CPUI_INT_OR(v1, v2, opSize);

	//SF = uResult < #0x0:opSize
	auto regSF = data.getArch()->translate->getRegister("SF");
	ghidra::PcodeOp* opSless = data.newOp(2, pc);
	data.opSetOpcode(opSless, ghidra::CPUI_INT_SLESS);
	data.newVarnodeOut(regSF.size, regSF.getAddr(), opSless);
	data.opSetInput(opSless, uResult, 0);
	data.opSetInput(opSless, data.newConstant(opSize, 0x0), 1);

	//ZF = uResult == #0x0:opSize
	auto regZF = data.getArch()->translate->getRegister("ZF");
	ghidra::PcodeOp* opEqual = data.newOp(2, pc);
	data.opSetOpcode(opEqual, ghidra::CPUI_INT_EQUAL);
	data.newVarnodeOut(regZF.size, regZF.getAddr(), opEqual);
	data.opSetInput(opEqual, uResult, 0);
	data.opSetInput(opEqual, data.newConstant(opSize, 0x0), 1);

	//uCheck1 = uResult & #0xff:opSize
	ghidra::Varnode* uCheck1 = opBuilder.CPUI_INT_AND(uResult, data.newConstant(opSize, 0xFF), opSize);

	//uCheck2 = POPCOUNT(uCheck1)
	ghidra::Varnode* uCheck2 = opBuilder.CPUI_POPCOUNT(uCheck1, 0x1);

	//uCheck3 = uCheck2 & #0x1:1
	ghidra::Varnode* uCheck3 = opBuilder.CPUI_INT_AND(uCheck2, data.newConstant(0x1, 0x1), 0x1);

	//PF = uCheck3 == #0x0:1
	auto regPF = data.getArch()->translate->getRegister("PF");
	opEqual = data.newOp(2, pc);
	data.opSetOpcode(opEqual, ghidra::CPUI_INT_EQUAL);
	data.newVarnodeOut(regPF.size, regPF.getAddr(), opEqual);
	data.opSetInput(opEqual, uCheck3, 0);
	data.opSetInput(opEqual, data.newConstant(0x1, 0x0), 1);

	return uResult;
}

ghidra::Varnode* FuncBuildHelper::BuildAdd(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2, size_t opsize)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regCF = data.getArch()->translate->getRegister("CF");
	auto regOF = data.getArch()->translate->getRegister("OF");
	auto regSF = data.getArch()->translate->getRegister("SF");
	auto regZF = data.getArch()->translate->getRegister("ZF");
	auto regPF = data.getArch()->translate->getRegister("PF");

	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);

	//CF = CARRY4(v1,v2)
	ghidra::PcodeOp* opCarry = data.newOp(2, pc);
	data.opSetOpcode(opCarry, ghidra::CPUI_INT_CARRY);
	data.newVarnodeOut(regCF.size, regCF.getAddr(), opCarry);
	data.opSetInput(opCarry, v1, 0);
	data.opSetInput(opCarry, v2, 1);

	//OF = SCARRY4(v1,v2)
	ghidra::PcodeOp* opScarry = data.newOp(2, pc);
	data.opSetOpcode(opScarry, ghidra::CPUI_INT_SCARRY);
	data.newVarnodeOut(regOF.size, regOF.getAddr(), opScarry);
	data.opSetInput(opScarry, v1, 0);
	data.opSetInput(opScarry, v2, 1);

	//uOut = v1 + v2
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	ghidra::Varnode* uniqOut = data.newUniqueOut(opsize, opAdd);
	data.opSetInput(opAdd, v1, 0);
	data.opSetInput(opAdd, v2, 1);

	//SF = uOut < #0x0
	ghidra::PcodeOp* opSless = data.newOp(2, pc);
	data.opSetOpcode(opSless, ghidra::CPUI_INT_SLESS);
	data.newVarnodeOut(regSF.size, regSF.getAddr(), opSless);
	data.opSetInput(opSless, uniqOut, 0);
	data.opSetInput(opSless, data.newConstant(opsize, 0x0), 1);

	//ZF = uOut == #0x0
	ghidra::PcodeOp* opEqual1 = data.newOp(2, pc);
	data.opSetOpcode(opEqual1, ghidra::CPUI_INT_EQUAL);
	data.newVarnodeOut(regZF.size, regZF.getAddr(), opEqual1);
	data.opSetInput(opEqual1, uniqOut, 0);
	data.opSetInput(opEqual1, data.newConstant(opsize, 0x0), 1);

	//u1 = uOut & #0xff
	ghidra::PcodeOp* opAnd1 = data.newOp(2, pc);
	data.opSetOpcode(opAnd1, ghidra::CPUI_INT_AND);
	ghidra::Varnode* u1 = data.newUniqueOut(opsize, opAnd1);
	data.opSetInput(opAnd1, uniqOut, 0);
	data.opSetInput(opAnd1, data.newConstant(opsize, 0xFF), 1);

	//u2 = POPCOUNT(u1)
	ghidra::PcodeOp* opPopCount = data.newOp(1, pc);
	data.opSetOpcode(opPopCount, ghidra::CPUI_POPCOUNT);
	ghidra::Varnode* u2 = data.newUniqueOut(0x1, opPopCount);
	data.opSetInput(opPopCount, u1, 0);

	//u3 = u2 & #0x1:1
	ghidra::PcodeOp* opAnd2 = data.newOp(2, pc);
	data.opSetOpcode(opAnd2, ghidra::CPUI_INT_AND);
	ghidra::Varnode* u3 = data.newUniqueOut(0x4, opAnd2);
	data.opSetInput(opAnd2, u2, 0);
	data.opSetInput(opAnd2, data.newConstant(0x1, 0x1), 1);

	//PF = u3 == #0x0:1
	ghidra::PcodeOp* opEqual2 = data.newOp(2, pc);
	data.opSetOpcode(opEqual2, ghidra::CPUI_INT_EQUAL);
	data.newVarnodeOut(regPF.size, regPF.getAddr(), opEqual2);
	data.opSetInput(opEqual2, u3, 0);
	data.opSetInput(opEqual2, data.newConstant(0x1, 0x0), 1);

	return uniqOut;
}

ghidra::Varnode* FuncBuildHelper::BuildAnd(ghidra::Funcdata& data, size_t addr, ghidra::Varnode* v1, ghidra::Varnode* v2, size_t opSize)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr);
	PCodeBuildHelper opBuilder(data, pc);

	//CF = #0x0:1
	auto regCF = data.getArch()->translate->getRegister("CF");
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regCF.size, regCF.getAddr(), opCopy);
	data.opSetInput(opCopy, data.newConstant(0x1, 0x0), 0);

	//OF = #0x0:1
	auto regOF = data.getArch()->translate->getRegister("OF");
	opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regOF.size, regOF.getAddr(), opCopy);
	data.opSetInput(opCopy, data.newConstant(0x1, 0x0), 0);

	//uResult = v1 & v2
	ghidra::Varnode* uResult = opBuilder.CPUI_INT_AND(v1, v2, opSize);

	//SF = uResult < #0x0
	auto regSF = data.getArch()->translate->getRegister("SF");
	ghidra::PcodeOp* opSless = data.newOp(2, pc);
	data.opSetOpcode(opSless, ghidra::CPUI_INT_SLESS);
	data.newVarnodeOut(regSF.size, regSF.getAddr(), opSless);
	data.opSetInput(opSless, uResult, 0);
	data.opSetInput(opSless, data.newConstant(opSize, 0x0), 1);

	//ZF = uResult == #0x0
	auto regZF = data.getArch()->translate->getRegister("ZF");
	ghidra::PcodeOp* opEqual = data.newOp(2, pc);
	data.opSetOpcode(opEqual, ghidra::CPUI_INT_EQUAL);
	data.newVarnodeOut(regZF.size, regZF.getAddr(), opEqual);
	data.opSetInput(opEqual, uResult, 0);
	data.opSetInput(opEqual, data.newConstant(opSize, 0x0), 1);

	//uCheck1 = uResult & #0xff
	ghidra::Varnode* uCheck1 = opBuilder.CPUI_INT_AND(uResult, data.newConstant(opSize, 0xFF), opSize);

	//uCheck2 = POPCOUNT(uCheck1)
	ghidra::Varnode* uCheck2 = opBuilder.CPUI_POPCOUNT(uCheck1, 0x1);

	//uCheck3 = uCheck2 & #0x1:1
	ghidra::Varnode* uCheck3 = opBuilder.CPUI_INT_AND(uCheck2, data.newConstant(0x1, 0x1), opSize);

	//PF = uCheck3 == #0x0:1
	auto regPF = data.getArch()->translate->getRegister("PF");
	opEqual = data.newOp(2, pc);
	data.opSetOpcode(opEqual, ghidra::CPUI_INT_EQUAL);
	data.newVarnodeOut(regPF.size, regPF.getAddr(), opEqual);
	data.opSetInput(opEqual, uCheck3, 0);
	data.opSetInput(opEqual, data.newConstant(0x1, 0x0), 1);

	return uResult;
}