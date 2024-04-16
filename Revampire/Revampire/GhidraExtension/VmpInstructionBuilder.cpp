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

int VmpOpPushVSP::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//uEsp = ESP(free)
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Varnode* uEsp = data.newUniqueOut(4, opCopy);
	data.opSetInput(opCopy, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);

	//ESP = ESP - #0x4
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(0x4, 0x4), 1);

	//*(ram,ESP) = uEsp
	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	data.opSetInput(opStore, uEsp, 2);

	return 3;
}

//vPushReg1
//movzx ecx,byte ptr ds:[vmCode]
//movzx ax,byte ptr ss:[esp+ecx]
//sub vmStack,0x2
//mov word ptr ds:[vmStack],ax

//vPushReg2
//movzx edx, byte ptr ds:[vmCode]
//mov cx, word ptr ss:[esp+edx]
//sub vmStack, 0x2
//mov word ptr ds:[vmStack], cx

//vPushReg4
//movzx ecx, byte ptr ds:[vmCode]
//mov edx, dword ptr ss:[esp+ecx]
//lea vmStack, ss:[vmStack-0x4]
//mov dword ptr ss:[vmStack], edx

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

//PushImm1
//movzx ecx,byte ptr ss:[ebp]
//lea esi,dword ptr ds:[esi-0x2]
//mov word ptr ds:[esi],cx

//PushImm2
//movzx edx,word ptr ds:[esi]
//sub edi,0x2
//mov word ptr ds:[edi],dx

//PushImm4
//mov eax,dword ptr ds:[esi]
//lea esi,dword ptr ds:[esi+0x4]
//mov dword ptr ds:[edi],eax

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

//mov edx, dword ptr ss:[vmstack]
//add vmStack, 0x4
//mov vmCode,edx
//mov newStack,vmStack

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


//vPopReg2
//cx  =  word:[vsp]
//vsp = vsp + 2
//word:[vReg], cx

//vPopReg4
//ecx,dword ptr ds:[vsp]
//vsp = vsp + 4
//dword:[vReg],ecx

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

int VmpOpExit::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	for (unsigned int n = 0; n < exitContext.size(); ++n) {
		ghidra::PcodeOp* opLoad = data.newOp(2, pc);
		data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
		data.newVarnodeOut(exitContext[n].size, exitContext[n].getAddr(), opLoad);
		data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
		data.opSetInput(opLoad, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
		//esp = esp + 0x4
		ghidra::PcodeOp* opAdd = data.newOp(2, pc);
		data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
		data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
		data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);
	}
	return exitContext.size();
}

int VmpOpReadMem::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.raw);

	//readAddr = *(ram,ESP(free))
	ghidra::PcodeOp* opLoad1 = data.newOp(2, pc);
	data.opSetOpcode(opLoad1, ghidra::CPUI_LOAD);
	ghidra::Varnode* uReadAddr = data.newUniqueOut(4, opLoad1);
	data.opSetInput(opLoad1, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad1, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//readVal = *(ram,readAddr)
	ghidra::PcodeOp* opLoad2 = data.newOp(2, pc);
	data.opSetOpcode(opLoad2, ghidra::CPUI_LOAD);
	ghidra::Varnode* uReadVal = data.newUniqueOut(opSize, opLoad2);
	data.opSetInput(opLoad2, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad2, uReadAddr, 1);

	//esp = esp + offset
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	if (opSize == 0x4) {
		data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);
	}
	else {
		//to do...check
		data.opSetInput(opAdd, data.newConstant(4, 0x2), 1);
	}

	//*(ram,ESP(free)) = readVal
	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	data.opSetInput(opStore, uReadVal, 2);

	return 0x4;
}

int VmpOpWriteMem::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//writeAddr = *(ram,ESP(free))
	ghidra::PcodeOp* opLoad1 = data.newOp(2, pc);
	data.opSetOpcode(opLoad1, ghidra::CPUI_LOAD);
	ghidra::Varnode* uWriteAddr = data.newUniqueOut(4, opLoad1);
	data.opSetInput(opLoad1, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad1, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//ESP = #0x4 + ESP
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newConstant(0x4, 0x4), 0);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//writeVal = *(ram,ESP(free))
	ghidra::PcodeOp* opLoad2 = data.newOp(2, pc);
	data.opSetOpcode(opLoad2, ghidra::CPUI_LOAD);
	ghidra::Varnode* uWriteVal = data.newUniqueOut(4, opLoad2);
	data.opSetInput(opLoad2, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad2, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//*[writeAddr] = writeVal
	ghidra::PcodeOp* opStore = data.newOp(3, pc);
	data.opSetOpcode(opStore, ghidra::CPUI_STORE);
	data.opSetInput(opStore, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opStore, uWriteAddr, 1);
	data.opSetInput(opStore, uWriteVal, 2);

	//ESP = #0x4 + ESP
	opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newConstant(0x4, 0x4), 0);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	return 5;
}

//vNand1
//movzx ax,byte ptr ss:[ebp]
//mov dl,byte ptr ss:[ebp+0x2]
//lea ebp,dword ptr ss:[ebp-0x2]
//not al
//not dl
//or al,dl
//mov word ptr ss:[ebp+0x4],ax
//pushfd
//pop dword ptr ds:[edi]

int VmpOpNand::BuildNand1(ghidra::Funcdata& data)
{
	//To do...
	return 0x0;
}

int VmpOpNand::BuildNand2(ghidra::Funcdata& data)
{
	//To do...
	return 0x0;
}

//vNand4
//mov edx,dword ptr ds:[edi]
//mov ecx,dword ptr ds:[edi+0x4]
//not edx
//not ecx
//or edx,ecx
//mov dword ptr ds:[edi+0x4],edx
//pushfd
//pop dword ptr ds:[edi]

int VmpOpNand::BuildNand4(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");

	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uAddr = esp + 0x4
	ghidra::Varnode* uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x4), 0x4);

	//u2 = *(ram,uAddr)
	ghidra::Varnode* u2 = opBuilder.CPUI_LOAD(uAddr, 0x4);

	//u11 = ~u1
	ghidra::Varnode* u11 = opBuilder.CPUI_INT_NEGATE(u1, opSize);

	//u22 = ~u2
	ghidra::Varnode* u22 = opBuilder.CPUI_INT_NEGATE(u2, opSize);

	//uOrResult = u11 | u22
	ghidra::Varnode* uOrResult = opBuilder.CPUI_INT_OR(u11, u22, opSize);

	//eflags = u11 | u22
	ghidra::PcodeOp* opOr = data.newOp(2, pc);
	data.opSetOpcode(opOr, ghidra::CPUI_INT_OR);
	data.newVarnodeOut(regEFlags.size, regEFlags.getAddr(), opOr);
	data.opSetInput(opOr, u11, 0);
	data.opSetInput(opOr, u22, 1);

	//*(ram,esp+0x4) = uOrResult
	opBuilder.CPUI_STORE(uAddr, uOrResult);

	//*(ram,ESP) = eflags
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x9;
}



int VmpOpNand::BuildInstruction(ghidra::Funcdata& data)
{
	if (opSize == 0x4) {
		return BuildNand4(data);
	}
	if (opSize == 0x2) {
		return BuildNand2(data);
	}
	if (opSize == 0x1) {
		return BuildNand1(data);
	}
	return 0x0;
}

//mov edi,dword ptr ds:[edi]
//等价于mov esp,[esp]

int VmpOpWriteVSP::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.raw);

	//u1 = *(ram,ESP)
	ghidra::PcodeOp* opLoad = data.newOp(2, pc);
	data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
	ghidra::Varnode* u1 = data.newUniqueOut(0x4, opLoad);
	data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//ESP = u1
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opCopy);
	data.opSetInput(opCopy, u1, 0);

	return 0x2;
}


int VmpOpShr::BuildShr1(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::Varnode* uEax = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uEsp4 = #0x2 + ESP
	ghidra::Varnode* uEsp4 = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);

	//uCL = *(ram,uEsp4)
	ghidra::Varnode* uCL = opBuilder.CPUI_LOAD(uEsp4, 0x1);

	//ESP = ESP(free) - #0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//转换SHR指令
	ghidra::Varnode* uResult = FuncBuildHelper::BuildShr(data, addr.vmdata, uEax, uCL);

	//uEsp4 = #0x4 + ESP
	uEsp4 = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,uEsp4) = uResult
	opBuilder.CPUI_STORE(uEsp4, uResult);

	//pushfd
	//pop[esp]
	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpShr::BuildShr2(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::Varnode* uEax = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uEsp4 = #0x2 + ESP
	ghidra::Varnode* uEsp4 = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);

	//uCL = *(ram,uEsp4)
	ghidra::Varnode* uCL = opBuilder.CPUI_LOAD(uEsp4, 0x1);

	//ESP = ESP(free) - #0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//转换SHR指令
	ghidra::Varnode* uResult = FuncBuildHelper::BuildShr(data, addr.vmdata, uEax, uCL);

	//uEsp4 = #0x4 + ESP
	uEsp4 = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,uEsp4) = uResult
	opBuilder.CPUI_STORE(uEsp4, uResult);

	//pushfd
	//pop[esp]
	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpShr::BuildShr4(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::Varnode* uEax = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uEsp4 = #0x4 + ESP
	ghidra::Varnode* uEsp4 = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x4), 0x4);

	//uCL = *(ram,uEsp4)
	ghidra::Varnode* uCL = opBuilder.CPUI_LOAD(uEsp4, 0x1);

	//ESP = ESP(free) - #0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//转换SHR指令
	ghidra::Varnode* uResult = FuncBuildHelper::BuildShr(data, addr.vmdata, uEax, uCL);

	//uEsp4 = #0x4 + ESP
	uEsp4 = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,uEsp4) = uResult
	opBuilder.CPUI_STORE(uEsp4, uResult);

	//pushfd
	//pop[esp]
	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpShr::BuildInstruction(ghidra::Funcdata& data)
{
	if (opSize == 0x4) {
		return BuildShr4(data);
	}
	if (opSize == 0x2) {
		return BuildShr2(data);
	}
	if (opSize == 0x1) {
		return BuildShr1(data);
	}
	return 0x0;
}

int VmpOpShl::BuildShl1(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::Varnode* uEax = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uShiftAddr = #0x2 + ESP
	ghidra::Varnode* uShiftAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(0x4, 0x2), 0x4);

	//uCL = *(uShiftAddr)
	ghidra::Varnode* uCL = opBuilder.CPUI_LOAD(uShiftAddr, 0x1);

	//ESP = ESP - #0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//转换SHL指令
	ghidra::Varnode* uResult = FuncBuildHelper::BuildShl(data, addr.vmdata, uEax, uCL);

	//uWriteVarAddr = #0x4 + ESP
	ghidra::Varnode* uWriteVarAddr = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,uEsp4) = uResult
	opBuilder.CPUI_STORE(uWriteVarAddr, uResult);

	//pushfd
	//pop[esp]
	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpShl::BuildShl2(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::Varnode* uEax = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uShiftAddr = #0x2 + ESP
	ghidra::Varnode* uShiftAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);

	//uCL = *(uShiftAddr)
	ghidra::Varnode* uCL = opBuilder.CPUI_LOAD(uShiftAddr, 0x1);

	//ESP = ESP - #0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//转换SHL指令
	ghidra::Varnode* uResult = FuncBuildHelper::BuildShl(data, addr.vmdata, uEax, uCL);

	//uWriteVarAddr = #0x4 + ESP
	ghidra::Varnode* uWriteVarAddr = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,uEsp4) = uResult
	opBuilder.CPUI_STORE(uWriteVarAddr, uResult);

	//pushfd
	//pop[esp]
	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpShl::BuildShl4(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::PcodeOp* opLoad = data.newOp(2, pc);
	data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
	ghidra::Varnode* uEax = data.newUniqueOut(4, opLoad);
	data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//uEsp4 = #0x4 + ESP
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	ghidra::Varnode* uEsp4 = data.newUniqueOut(4, opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);

	//uCL = *(ram,uEsp4)
	opLoad = data.newOp(2, pc);
	data.opSetOpcode(opLoad, ghidra::CPUI_LOAD);
	ghidra::Varnode* uCL = data.newUniqueOut(1, opLoad);
	data.opSetInput(opLoad, data.newVarnodeSpace(data.getArch()->getSpaceByName("ram")), 0);
	data.opSetInput(opLoad, uEsp4, 1);

	//ESP = ESP(free) - #0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//转换SHL指令
	ghidra::Varnode* uResult = FuncBuildHelper::BuildShl(data, addr.vmdata, uEax, uCL);

	//uEsp4 = #0x4 + ESP
	uEsp4 = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,uEsp4) = uResult
	opBuilder.CPUI_STORE(uEsp4, uResult);

	//pushfd
	//pop[esp]
	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpShl::BuildInstruction(ghidra::Funcdata& data)
{
	if (opSize == 0x4) {
		return BuildShl4(data);
	}
	if (opSize == 0x2) {
		return BuildShl2(data);
	}
	if (opSize == 0x1) {
		return BuildShl1(data);
	}
	return 0x0;
}

int VmpOpNor::BuildNor1(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uAddr = esp + 0x4
	ghidra::Varnode* uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);

	//u2 = *(ram,uAddr)
	ghidra::Varnode* u2 = opBuilder.CPUI_LOAD(uAddr, opSize);

	//esp = esp - 0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//u11 = ~u1
	ghidra::Varnode* u11 = opBuilder.CPUI_INT_NEGATE(u1, opSize);

	//u22 = ~u2
	ghidra::Varnode* u22 = opBuilder.CPUI_INT_NEGATE(u2, opSize);

	ghidra::Varnode* uAndResult = FuncBuildHelper::BuildAnd(data, addr.vmdata, u11, u22, opSize);

	//uWriteVarAddr = #0x4 + ESP(free)
	ghidra::Varnode* uWriteVarAddr = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,esp+0x4) = uAndResult
	opBuilder.CPUI_STORE(uWriteVarAddr, uAndResult);

	FuncBuildHelper::BuildEflags(data, addr.vmdata);

	//*(ram,ESP) = eflags
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpNor::BuildNor2(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uAddr = esp + 0x4
	ghidra::Varnode* uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);

	//u2 = *(ram,uAddr)
	ghidra::Varnode* u2 = opBuilder.CPUI_LOAD(uAddr, opSize);

	//esp = esp - 0x2
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0x2), 1);

	//u11 = ~u1
	ghidra::Varnode* u11 = opBuilder.CPUI_INT_NEGATE(u1, opSize);

	//u22 = ~u2
	ghidra::Varnode* u22 = opBuilder.CPUI_INT_NEGATE(u2, opSize);

	ghidra::Varnode* uAndResult = FuncBuildHelper::BuildAnd(data, addr.vmdata, u11, u22, opSize);

	//uWriteVarAddr = #0x4 + ESP(free)
	ghidra::Varnode* uWriteVarAddr = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*(ram,esp+0x4) = uAndResult
	opBuilder.CPUI_STORE(uWriteVarAddr, uAndResult);

	FuncBuildHelper::BuildEflags(data, addr.vmdata);

	//*(ram,ESP) = eflags
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpNor::BuildNor4(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//uAddr = esp + 0x4
	ghidra::Varnode* uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x4), 0x4);

	//u2 = *(ram,uAddr)
	ghidra::Varnode* u2 = opBuilder.CPUI_LOAD(uAddr, opSize);

	//u11 = ~u1
	ghidra::Varnode* u11 = opBuilder.CPUI_INT_NEGATE(u1, opSize);

	//u22 = ~u2
	ghidra::Varnode* u22 = opBuilder.CPUI_INT_NEGATE(u2, opSize);

	//uAndResult = u11 & u22
	ghidra::Varnode* uAndResult = opBuilder.CPUI_INT_AND(u11, u22, opSize);

	//eflags = u11 & u22
	ghidra::PcodeOp* opAnd = data.newOp(2, pc);
	data.opSetOpcode(opAnd, ghidra::CPUI_INT_AND);
	data.newVarnodeOut(regEFlags.size, regEFlags.getAddr(), opAnd);
	data.opSetInput(opAnd, u11, 0);
	data.opSetInput(opAnd, u22, 1);

	//*(ram,esp+0x4) = uAndResult
	opBuilder.CPUI_STORE(uAddr, uAndResult);

	//*(ram,ESP) = eflags
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x10;
}

int VmpOpNor::BuildInstruction(ghidra::Funcdata& data)
{
	if (opSize == 0x4) {
		return BuildNor4(data);
	}
	if (opSize == 0x2) {
		return BuildNor2(data);
	}
	if (opSize == 0x1) {
		return BuildNor1(data);
	}
	return 0x0;
}