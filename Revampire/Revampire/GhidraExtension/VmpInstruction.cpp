#include "VmpInstruction.h"
#include "../GhidraExtension/FuncBuildHelper.h"

int VmpInstruction::BuildInstruction(ghidra::Funcdata& data)
{
	return 0x0;
}

int VmpOpInit::BuildInstruction(ghidra::Funcdata& data)
{
	int step = 0x0;
	for (const auto& context : storeContext) {
		if (context.getAddr().getSpace()->getName() == "const") {
			FuncBuildHelper::BuildPushConst(data, addr.vmdata, context.getAddr().getOffset(), 0x4);
			step++;
		}
		else if (context.getAddr().getSpace()->getName() == "register") {
			FuncBuildHelper::BuildPushRegister(data, addr.vmdata, context);
			step++;
		}
	}
	return step;
}

int VmpOpPushReg::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");

	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//uniq = stack_context
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Varnode* uniqData = data.newUniqueOut(opSize, opCopy);
	data.opSetInput(opCopy, data.newVarnode(opSize, data.getArch()->getStackSpace(), uint32_t(vmRegOffset)), 0);

	//esp = esp - pushOffset
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	if (opSize == 0x4) {
		data.opSetInput(opSub, data.newConstant(4, 0x4), 1);
	}
	else {
		data.opSetInput(opSub, data.newConstant(4, 0x2), 1);
	}

	//*[esp] = uniq
	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	data.opSetInput(opStore, uniqData, 2);
	return 3;
}

int VmpOpPushImm::BuildPushImm1(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//uniqReg = constant
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Varnode* uniqReg = data.newUniqueOut(opSize, opCopy);
	data.opSetInput(opCopy, data.newConstant(opSize, immVal), 0);

	//ESP = ESP - 0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//*(ram,ESP(free)) = u0x00009a80:2(free)
	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	data.opSetInput(opStore, uniqReg, 2);

	return 0x3;
}

int VmpOpPushImm::BuildPushImm2(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//uniqReg = constant
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Varnode* uniqReg = data.newUniqueOut(opSize, opCopy);
	data.opSetInput(opCopy, data.newConstant(opSize, immVal), 0);

	//ESP = ESP - 0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//*(ram,ESP(free)) = u0x00009a80:2(free)
	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	data.opSetInput(opStore, uniqReg, 2);

	return 0x3;
}

int VmpOpPushImm::BuildPushImm4(ghidra::Funcdata& data)
{
	FuncBuildHelper::BuildPushConst(data, addr.vmdata, immVal, opSize);
	return 0x3;
}

int VmpOpPushImm::BuildInstruction(ghidra::Funcdata& data)
{
	if (opSize == 0x4) {
		return BuildPushImm4(data);
	}
	if (opSize == 0x2) {
		return BuildPushImm2(data);
	}
	if (opSize == 0x1) {
		return BuildPushImm1(data);
	}
	return 0x0;
}

int VmpOpJmp::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::PcodeOp* opLoad = data.newOp(2, pc);
	data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
	ghidra::Varnode* u1 = data.newUniqueOut(4, opLoad);
	data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//esp = esp + 0x4
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);

	//EIP = u1
	auto regEIP = data.getArch()->translate->getRegister("EIP");
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regEIP.size, regEIP.getAddr(), opCopy);
	data.opSetInput(opCopy, u1, 0);

	return 0x3;
}

int VmpOpPopReg::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	ghidra::PcodeOp* opLoad = data.newOp(2, pc);
	data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
	ghidra::Varnode* uniqOut = data.newUniqueOut(opSize, opLoad);
	data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//堆栈也有大小
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Address stackOffset(data.getArch()->getStackSpace(), uint32_t(vmRegOffset));
	data.newVarnodeOut(opSize, stackOffset, opCopy);
	opCopy->getOut()->setStackStore();
	data.opSetInput(opCopy, uniqOut, 0);

	//esp = esp + popOffset
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	if (opSize == 0x4) {
		data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);
	}
	else {
		data.opSetInput(opAdd, data.newConstant(4, 0x2), 1);
	}
	return 3;
}