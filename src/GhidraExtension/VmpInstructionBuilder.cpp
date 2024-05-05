#include "VmpInstruction.h"
#include "../GhidraExtension/FuncBuildHelper.h"


#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

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
//movzx ax,byte:[vREG]
//VSP = VSP - 0x2
//mov word ptr ds:[VSP],ax

//vPushReg2
//mov cx, word ptr ss:[vREG]
//VSP = VSP - 0x2
//mov word ptr ds:[VSP], cx

//vPushReg4
//mov edx, dword ptr ss:[vREG]
//VSP = VSP - 0x4
//mov dword ptr ss:[VSP], edx

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


//PushImm1
//movzx ecx,byte ptr ss:[vCode]
//VSP = VSP - 0x2
//mov word ptr ds:[VSP],cx

//PushImm2
//movzx edx,word ptr ds:[vCode]
//VSP = VSP - 0x2
//mov word ptr ds:[VSP],dx

//PushImm4
//mov eax,dword ptr ds:[vCode]
//VSP = VSP - 0x4
//mov dword ptr ds:[VSP],eax

int VmpOpPushImm::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	PCodeBuildHelper opBuilder(data, pc);
	//uniqReg = constant
	ghidra::Varnode* uniqReg = opBuilder.CPUI_COPY(data.newConstant(opSize, immVal), opSize);
	//regESP = regESP - valSize
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
	//*(ram,ESP(free)) = uniqReg
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), uniqReg);
	return 0x1;
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

	if (isBuildJmp) {
		ghidra::PcodeOp* opBranch = data.newOp(1, pc);
		data.opSetOpcode(opBranch, ghidra::CPUI_BRANCH);
		data.opSetInput(opBranch, data.newVarnode(0x1, data.getArch()->getSpaceByName("ram"), branchList[0]), 0);
	}
	else {
		//EIP = u1
		auto regEIP = data.getArch()->translate->getRegister("EIP");
		ghidra::PcodeOp* opCopy = data.newOp(1, pc);
		data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
		data.newVarnodeOut(regEIP.size, regEIP.getAddr(), opCopy);
		data.opSetInput(opCopy, u1, 0);
	}
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

	PCodeBuildHelper opBuilder(data, pc);

	//uniqOut = *[vsp]
	ghidra::Varnode* uniqOut = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//vm_reg = uniqOut
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	ghidra::Address stackOffset(data.getArch()->getStackSpace(), uint32_t(vmRegOffset));
	data.newVarnodeOut(opSize, stackOffset, opCopy);
	opCopy->getOut()->setStackStore();
	data.opSetInput(opCopy, uniqOut, 0);

	//vsp = vsp + popOffset
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
		if (exitContext[n] == regESP) {
			continue;
		}
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
	if (exitAddress) {
		ghidra::PcodeOp* opBranch = data.newOp(1, pc);
		data.opSetOpcode(opBranch, ghidra::CPUI_BRANCH);
		data.opSetInput(opBranch, data.newVarnode(0x1, data.getArch()->getSpaceByName("ram"), exitAddress), 0);
	}
	return 0x1;
}

//vReadMem4
//mov eax,dword ptr ss:[VSP]
//mov edx,dword ptr ss:[eax]
//mov dword ptr ss:[VSP],edx

//vReadMem2
//mov ecx,dword ptr ss:[VSP]
//mov ax,word ptr ss:[ecx]
//VSP = VSP + 0x2
//mov word ptr ss:[ebp],ax

int VmpOpReadMem::BuildInstruction(ghidra::Funcdata& data)
{
	int opCount = 0x0;
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.raw);
	PCodeBuildHelper opBuilder(data, pc);

	//readAddr = *(ram,ESP(free))
	ghidra::Varnode* uReadAddr = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);
	opCount++;

	//readVal = *(ram,readAddr)
	ghidra::Varnode* uReadVal = opBuilder.CPUI_LOAD(uReadAddr,opSize);
	opCount++;

	//esp = esp + 0x2
	if (opSize != 0x4) {
		ghidra::PcodeOp* opAdd = data.newOp(2, pc);
		data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
		data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
		data.opSetInput(opAdd, data.newConstant(4, 0x2), 1);
		opCount++;
	}

	//*(ram,ESP(free)) = readVal
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), uReadVal);
	opCount++;

	return opCount;
}

//vWriteMem4
//mov eax,dword ptr ds:[VSP]
//mov edx,dword ptr ds:[VSP+0x4]
//VSP = VSP + 0x8
//mov dword ptr ss:[eax],edx

//vWriteMem2
//mov eax, dword ptr ds:[VSP]
//mov dx, word ptr ds:[VSP+0x4]
//VSP = VSP + 0x6
//mov word ptr ds:[eax], dx

//vWriteMem1
//mov edx, dword ptr ds:[VSP]
//mov al, byte ptr ds:[VSP+0x4]
//VSP = VSP + 0x6
//mov byte ptr ds:[edx], al

int VmpOpWriteMem::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//writeAddr = *(ram,ESP(free))
	ghidra::Varnode* uWriteAddr = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//ESP = #0x4 + ESP
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newConstant(0x4, 0x4), 0);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);

	//writeVal = *(ram,ESP(free))
	ghidra::Varnode* uWriteVal = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	//*[writeAddr] = writeVal
	opBuilder.CPUI_STORE(uWriteAddr, uWriteVal);

	if (opSize == 0x4) {
		//ESP = #0x4 + ESP
		opAdd = data.newOp(2, pc);
		data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
		data.opSetInput(opAdd, data.newConstant(0x4, 0x4), 0);
		data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	}
	else {
		//ESP = #0x2 + ESP
		opAdd = data.newOp(2, pc);
		data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
		data.opSetInput(opAdd, data.newConstant(0x4, 0x2), 0);
		data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 1);
	}
	return 1;
}

//vNand1
//movzx ax,byte ptr ss:[VSP]
//mov dl,byte ptr ss:[VSP+0x2]
//VSP = VSP - 0x2
//not al
//not dl
//or al,dl
//mov word ptr ss:[VSP+0x4],ax
//pushfd
//pop dword ptr ds:[VSP]

//vNand4
//mov edx,dword ptr ds:[VSP]
//mov ecx,dword ptr ds:[VSP+0x4]
//not edx
//not ecx
//or edx,ecx
//mov dword ptr ds:[VSP+0x4],edx
//pushfd
//pop dword ptr ds:[VSP]


int VmpOpNand::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset),opSize);

	ghidra::Varnode* uAddr;
	if (opSize == 0x4) {
		//uAddr = esp + 0x4
		uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x4), 0x4);
	}
	else {
		//uAddr = esp + 0x2
		uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);
	}

	//u2 = *(ram,uAddr)
	ghidra::Varnode* u2 = opBuilder.CPUI_LOAD(uAddr, opSize);

	if (opSize != 0x4) {
		//esp = esp - 0x2
		ghidra::PcodeOp* opSub = data.newOp(2, pc);
		data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
		data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
		data.opSetInput(opSub, data.newConstant(4, 0x2), 1);
	}

	//u11 = ~u1
	ghidra::Varnode* u11 = opBuilder.CPUI_INT_NEGATE(u1, opSize);

	//u22 = ~u2
	ghidra::Varnode* u22 = opBuilder.CPUI_INT_NEGATE(u2, opSize);

	ghidra::Varnode* uOrResult = FuncBuildHelper::BuildOr(data, addr.vmdata, u11, u22, opSize);

	//u4 = #0x4 + ESP(free)
	ghidra::Varnode* uWriteVarAddr = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);

	//*[u4] = uniqOut
	opBuilder.CPUI_STORE(uWriteVarAddr, uOrResult);

	FuncBuildHelper::BuildEflags(data, addr.vmdata);

	//*(ram,ESP) = eflags
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x1;
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

	return 0x1;
}


//vShr1
//movzx ax, byte ptr ds:[VSP]
//mov cl, byte ptr ds:[VSP+0x2]
//VSP = VSP - 0x2
//shr al, cl
//mov word ptr ds:[VSP+0x4], ax
//pushfd
//pop dword ptr ds:[esi]

//vShr4
//mov edx, dword ptr ss:[VSP]
//mov cl, byte ptr ss:[VSP+0x4]
//VSP = VSP - 0x2
//shr edx, cl
//mov dword ptr ss:[VSP+0x4], edx
//pushfd
//pop dword ptr ss:[ebp]

int VmpOpShr::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//uEax = *(ram,ESP)
	ghidra::Varnode* uEax = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);
	ghidra::Varnode* uEsp4;
	if (opSize == 0x4) {
		//uEsp4 = #0x4 + ESP
		uEsp4 = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x4), 0x4);
	}
	else {
		//uEsp4 = #0x2 + ESP
		uEsp4 = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);
	}
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

	return 0x1;
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


//vNor1
//movzx ax,byte ptr ss:[VSP]
//mov cl,byte ptr ss:[VSP+0x2]
//VSP = VSP - 0x2
//not al
//not cl
//and al,cl
//mov word ptr ss:[VSP+0x4],ax
//pushfd
//pop dword ptr ss:[VSP]

//vNor4
//mov eax,dword ptr ss:[VSP]
//mov ecx,dword ptr ss:[VSP+0x4]
//not eax
//not ecx
//and eax,ecx
//mov dword ptr ss:[VSP+0x4],eax
//pushfd
//pop dword ptr ss:[VSP]

int VmpOpNor::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), opSize);

	ghidra::Varnode* uAddr;
	if (opSize == 0x4) {
		//uAddr = esp + 0x4
		uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x4), 0x4);
	}
	else {
		//uAddr = esp + 0x2
		uAddr = opBuilder.CPUI_INT_ADD(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newConstant(4, 0x2), 0x4);
	}
	//u2 = *(ram,uAddr)
	ghidra::Varnode* u2 = opBuilder.CPUI_LOAD(uAddr, opSize);

	if (opSize != 0x4) {
		//esp = esp - 0x2
		ghidra::PcodeOp* opSub = data.newOp(2, pc);
		data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
		data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
		data.opSetInput(opSub, data.newConstant(4, 0x2), 1);
	}

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

	return 0x1;
}

int UserOpConnect::BuildInstruction(ghidra::Funcdata& data)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.raw);
	ghidra::PcodeOp* opBranch = data.newOp(1, pc);
	data.opSetOpcode(opBranch, ghidra::CPUI_BRANCH);
	data.opSetInput(opBranch, data.newVarnode(0x1, data.getArch()->getSpaceByName("ram"), connectAddr), 0);
	return 0x1;
}


//vAdd1
//movzx dx,byte ptr ss:[VSP]
//mov al,byte ptr ss:[VSP+0x2]
//VSP = VSP - 0x2
//add dl,al
//mov word ptr ss:[VSP+0x4],dx
//pushfd
//pop dword ptr ss:[VSP]

//vAdd2
//mov dx,word ptr ss:[VSP]
//mov ax,word ptr ss:[VSP+0x2]
//VSP = VSP - 0x2
//add dx,ax
//mov word ptr ss:[VSP+0x4],dx
//pushfd
//pop dword ptr ss:[VSP]

//vAdd4
//mov eax,dword ptr ss:[VSP]
//mov ecx,dword ptr ss:[VSP+0x4]
//add eax,ecx
//mov dword ptr ss:[VSP+0x4],eax
//pushfd
//pop dword ptr ss:[VSP]

int VmpOpAdd::BuildInstruction(ghidra::Funcdata& data)
{
	auto regESP = data.getArch()->translate->getRegister("ESP");
	auto regEFlags = data.getArch()->translate->getRegister("eflags");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	PCodeBuildHelper opBuilder(data, pc);

	//u1 = *(ram,ESP)
	ghidra::Varnode* u1 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset),opSize);

	ghidra::Varnode* u2;
	//uEsp = #0x2 + uEsp(free)
	if (opSize == 0x4) {
		ghidra::Varnode* uEsp = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);
		u2 = opBuilder.CPUI_LOAD(uEsp, opSize);
	}
	else {
		ghidra::Varnode* uEsp = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x2), data.newVarnode(regESP.size, regESP.space, regESP.offset), 0x4);
		u2 = opBuilder.CPUI_LOAD(uEsp, opSize);
	}

	if (opSize != 4) {
		//ESP = ESP - 0x2
		ghidra::PcodeOp* opSub = data.newOp(2, pc);
		data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
		data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
		data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
		data.opSetInput(opSub, data.newConstant(4, 0x2), 1);
	}

	//uniqOut = u1 + u2
	ghidra::Varnode* uAddResult = FuncBuildHelper::BuildAdd(data, addr.vmdata, u1, u2, opSize);

	//uEsp = #0x4 + ESP(free)
	ghidra::Varnode* uEsp = opBuilder.CPUI_INT_ADD(data.newConstant(0x4, 0x4), data.newVarnode(regESP.size, regESP.space, regESP.offset),0x4);

	//*[uEsp] = uAddResult
	opBuilder.CPUI_STORE(uEsp, uAddResult);

	FuncBuildHelper::BuildEflags(data, addr.vmdata);
	
	//*(ram,ESP) = eflags
	opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), data.newVarnode(regEFlags.size, regEFlags.space, regEFlags.offset));

	return 0x1;
}

int VmpOpJmpConst::BuildInstruction(ghidra::Funcdata& data)
{
	if(!isBuildJmp){
		return 0x0;
	}
	auto regEIP = data.getArch()->translate->getRegister("EIP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	ghidra::PcodeOp* opBranch = data.newOp(1, pc);
	data.opSetOpcode(opBranch, ghidra::CPUI_BRANCH);
	data.opSetInput(opBranch, data.newVarnode(0x1, data.getArch()->getSpaceByName("ram"), targetAddr), 0);
	return 0x1;
}

int VmpOpExitCall::BuildInstruction(ghidra::Funcdata& data)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	auto regESP = data.getArch()->translate->getRegister("ESP");

	//弹出压入的返回值,esp = esp + 0x4
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);

	ghidra::PcodeOp* opCall = data.newOp(1, pc);
	data.opSetOpcode(opCall, ghidra::CPUI_CALL);
	data.opSetInput(opCall, data.newVarnode(0x1, data.getArch()->getSpaceByName("ram"), callAddr), 0);
	if (exitAddress) {
		ghidra::PcodeOp* opBranch = data.newOp(1, pc);
		data.opSetOpcode(opBranch, ghidra::CPUI_BRANCH);
		data.opSetInput(opBranch, data.newVarnode(0x1, data.getArch()->getSpaceByName("ram"), exitAddress), 0);
	}
	return 0x1;
}

//vPopfd
//popfd
//就等价于popfd指令

int VmpOpPopfd::BuildInstruction(ghidra::Funcdata& data)
{
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);
	auto regESP = data.getArch()->translate->getRegister("ESP");

	//暂时只处理成这样,
	//To do...
	//esp = esp + 0x4
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opAdd, data.newConstant(4, 0x4), 1);

	return 0x1;
}

//vCpuid
//mov eax, dword ptr ds:[VSP]
//cpuid
//VSP = VSP - 0xC
//mov dword ptr ds:[VSP+0xC], eax
//mov dword ptr ds:[VSP+0x8], ebx
//mov dword ptr ds:[VSP+0x4], ecx
//mov dword ptr ds:[VSP], edx


int VmpOpCpuid::BuildInstruction(ghidra::Funcdata& data)
{
	auto regEIP = data.getArch()->translate->getRegister("EIP");
	auto regESP = data.getArch()->translate->getRegister("ESP");

	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//To do...

	//esp = esp - 0xC
	ghidra::PcodeOp* opSub = data.newOp(2, pc);
	data.opSetOpcode(opSub, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
	data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opSub, data.newConstant(4, 0xC), 1);

	return 0x1;
}

//mov eax, dword ptr ds:[VSP]
//mov edx, dword ptr ds:[VSP+0x4]
//mov cl, byte ptr ds:[VSP+0x8]
//VSP = VSP + 0x2
//shld eax, edx, cl
//mov dword ptr ds:[VSP+0x4], eax
//pushfd
//pop dword ptr ds:[VSP]

int VmpOpShld::BuildInstruction(ghidra::Funcdata& data)
{
	auto regEIP = data.getArch()->translate->getRegister("EIP");
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//To do...
	//esp = esp + 0x2
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opAdd, data.newConstant(4, 0x2), 1);

	return 0x1;
}

//vShrd
//mov eax, dword ptr ds:[VSP]
//mov edx, dword ptr ds:[VSP+0x4]
//mov cl, byte ptr ds:[VSP+0x8]
//VSP = VSP + 0x2
//shrd eax, edx, cl
//mov dword ptr ds:[VSP+0x4], eax
//pushfd
//pop dword ptr ds:[VSP]

int VmpOpShrd::BuildInstruction(ghidra::Funcdata& data)
{
	auto regEIP = data.getArch()->translate->getRegister("EIP");
	auto regESP = data.getArch()->translate->getRegister("ESP");
	ghidra::Address pc = ghidra::Address(data.getArch()->getDefaultCodeSpace(), addr.vmdata);

	//To do...
	//esp = esp + 0x2
	ghidra::PcodeOp* opAdd = data.newOp(2, pc);
	data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
	data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
	data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
	data.opSetInput(opAdd, data.newConstant(4, 0x2), 1);

	return 0x1;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif

