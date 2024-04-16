#include "VmpNode.h"
#include "../Ghidra/funcdata.hh"
#include "../Ghidra/flow.hh"
#include "../Ghidra/action.hh"
#include "../Manager/DisasmManager.h"
#include "../GhidraExtension/FuncBuildHelper.h"
#include "../GhidraExtension/VmpControlFlow.h"
#include "../GhidraExtension/VmpFunction.h"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

int BuildVmRet(ghidra::Funcdata& data, ghidra::Address& addr)
{
    //return 0x0,第一个参数似乎必须是常量
    ghidra::PcodeOp* opReturn = data.newOp(1, addr);
    data.opSetOpcode(opReturn, ghidra::CPUI_RETURN);
    data.opSetInput(opReturn, data.newConstant(4, 0x0), 0);
    return 1;
}

int BuildVmCall(ghidra::Funcdata& data, ghidra::Address& pc)
{
    PCodeBuildHelper opBuilder(data, pc);
    auto regESP = data.getArch()->translate->getRegister("ESP");

    ghidra::Varnode* uniqConst = opBuilder.CPUI_COPY(data.newConstant(4, pc.getOffset() + 0x5),0x4);

    //esp = esp - 0x4
    ghidra::PcodeOp* opSub = data.newOp(2, pc);
    data.opSetOpcode(opSub, ghidra::CPUI_INT_SUB);
    data.newVarnodeOut(regESP.size, regESP.getAddr(), opSub);
    data.opSetInput(opSub, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
    data.opSetInput(opSub, data.newConstant(4, 0x4), 1);

    //[*esp] = addr
    opBuilder.CPUI_STORE(data.newVarnode(regESP.size, regESP.space, regESP.offset), uniqConst);
    return 3;
}

int BuildJmpReg(ghidra::Funcdata& data, ghidra::Address& pc, cs_insn* raw)
{
    std::string regName = GetX86RegName(raw->detail->x86.operands[0].reg);
    auto regJMP = data.getArch()->translate->getRegister(regName);
    auto regEIP = data.getArch()->translate->getRegister("EIP");
    //eip = eax
    ghidra::PcodeOp* opCopy = data.newOp(1, pc);
    data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
    data.newVarnodeOut(regEIP.size, regEIP.getAddr(), opCopy);
    data.opSetInput(opCopy, data.newVarnode(regJMP.size, regJMP.space, regJMP.offset), 0);
    return 1;
}

int BuildJmpImm(ghidra::Funcdata& data, ghidra::Address& pc, size_t jmpAddr)
{
	auto regEIP = data.getArch()->translate->getRegister("EIP");
	//eip = 0x123456
	ghidra::PcodeOp* opCopy = data.newOp(1, pc);
	data.opSetOpcode(opCopy, ghidra::CPUI_COPY);
	data.newVarnodeOut(regEIP.size, regEIP.getAddr(), opCopy);
    data.opSetInput(opCopy, data.newConstant(0x4, jmpAddr), 0);
	return 1;
}

int BuildPopIns(ghidra::Funcdata& data, ghidra::Address& pc, unsigned int offset)
{
    PCodeBuildHelper opBuilder(data, pc);
	ghidra::VarnodeData regESP = data.getArch()->translate->getRegister("ESP");

    //u2500 = #0x24 + ESP
	ghidra::Varnode* u2500 = opBuilder.CPUI_INT_ADD(data.newConstant(4, offset),
		data.newVarnode(regESP.size, regESP.space, regESP.offset), 4);

    //u7a00 = *(ram,ESP)
    ghidra::Varnode* u7a00 = opBuilder.CPUI_LOAD(data.newVarnode(regESP.size, regESP.space, regESP.offset), 4);

    //*(ram,u2500) = u7a00
    opBuilder.CPUI_STORE(u2500, u7a00);

    //ESP = ESP + 0x4
    ghidra::PcodeOp* opAdd = data.newOp(2, pc);
    data.opSetOpcode(opAdd, ghidra::CPUI_INT_ADD);
    data.newVarnodeOut(regESP.size, regESP.getAddr(), opAdd);
    data.opSetInput(opAdd, data.newVarnode(regESP.size, regESP.space, regESP.offset), 0);
    data.opSetInput(opAdd, data.newConstant(0x4, 0x4), 1);

    return 4;
}

void ghidra::FlowInfo::beginProcessInstruction(list<PcodeOp*>::const_iterator& oiter, bool& emptyflag)
{
	//先取出最后一个opcode
	if (obank.empty())
		emptyflag = true;
	else {
		emptyflag = false;
		oiter = obank.endDead();
		--oiter;
	}
}

void ghidra::FlowInfo::generateVmpFunctionOps(VmpFunction* vmFunc)
{
    VmpBasicBlock* bb = vmFunc->cfg.StartBlock();
    if (!bb) {
        return;
    }
    std::set<VmAddress> visited;
    std::vector<VmpBasicBlock*> blockList;
    blockList.push_back(bb);
	bool startbasic = true;
    while (!blockList.empty()) {
		VmpBasicBlock* curBlock = blockList.back();
		blockList.pop_back();
        if (visited.count(curBlock->blockEntry)) {
            continue;
        }
        visited.insert(curBlock->blockEntry);
        generateVmpBlockOps(curBlock, false);
        for (unsigned int n = 0; n < curBlock->outBlocks.size(); ++n) {
            blockList.push_back(curBlock->outBlocks[n]);
        }
    }
    return;
}

void ghidra::FlowInfo::generateVmpBlockOps(VmpBasicBlock* bblock, bool buildRet)
{
	clearProperties();
	bool isfallthru = false;
    bool startbasic = true;
	bool emptyflag;
	list<PcodeOp*>::const_iterator oiter;
    for (unsigned int n = 0; n < bblock->insList.size(); ++n) {
        beginProcessInstruction(oiter, emptyflag);
        int4 step = 0x0;
        ghidra::Address curaddr;
        if (bblock->insList[n]->IsRawInstruction()) {
            RawInstruction* rawIns = static_cast<RawInstruction*>(bblock->insList[n].get());
            curaddr = ghidra::Address(glb->getDefaultCodeSpace(), rawIns->raw->address);
            step = glb->translate->oneInstruction(emitter, curaddr);
        }
        else {
			VmpInstruction* vmIns = static_cast<VmpInstruction*>(bblock->insList[n].get());
            curaddr = ghidra::Address(glb->getDefaultCodeSpace(), vmIns->addr.vmdata);
			step = vmIns->BuildInstruction(data);
        }
		if (step) {
			VisitStat& stat(visited[curaddr]);
			stat.size = step;
			if (emptyflag) {
				oiter = obank.beginDead();
			}
			else {
				++oiter;
			}
			if (oiter != obank.endDead()) {
				stat.seqnum = (*oiter)->getSeqNum();
				data.opMarkStartInstruction(*oiter);
				xrefControlFlow(oiter, startbasic, isfallthru, (FuncCallSpecs*)0);
			}
		}
    }

	//判断有没有ret结尾
    if (buildRet) {
		VmpInstruction* endIns = static_cast<VmpInstruction*>(bblock->insList[bblock->insList.size() - 1].get());
		ghidra::Address endAddr(glb->getDefaultCodeSpace(), endIns->addr.vmdata);
		auto itEnd = std::prev(obank.endDead());
		if (itEnd != obank.endDead()) {
			if ((*itEnd)->code() != CPUI_RETURN) {
				BuildVmRet(data, endAddr);
			}
		}
    }
}

void ghidra::FlowInfo::generateVmpNodeOps(VmpNode* node)
{
    clearProperties();
    bool startbasic = true;
    bool isfallthru = false;
    bool emptyflag;
    list<PcodeOp*>::const_iterator oiter;
    for (unsigned int n = 0; n < node->addrList.size(); ++n) {
        ghidra::Address curaddr(glb->getDefaultCodeSpace(), node->addrList[n]);
        int4 step = 0x0;
        beginProcessInstruction(oiter, emptyflag);
		//再生成新的opcode
		auto asmData = DisasmManager::Main().DecodeInstruction(curaddr.getOffset());
		if (DisasmManager::IsE8Call(asmData->raw)) {
			step = BuildVmCall(data, curaddr);
		}
		//特殊的pop [esp]指令,Ghidra解析暂时有问题
		else if (asmData->raw->id == X86_INS_POP && asmData->raw->detail->x86.operands[0].mem.base == X86_REG_ESP) {
			step = BuildPopIns(data, curaddr, asmData->raw->detail->x86.operands[0].mem.disp + 0x4);
		}
		//jmp reg
		else if (asmData->raw->id == X86_INS_JMP && asmData->raw->detail->x86.operands[0].type == X86_OP_REG) {
			step = BuildJmpReg(data, curaddr, asmData->raw);
		}
        //jmp imm
        else if (asmData->raw->id == X86_INS_JMP && asmData->raw->detail->x86.operands[0].type == X86_OP_IMM) {
            step = BuildJmpImm(data, curaddr, asmData->raw->detail->x86.operands[0].imm);
        }
		//分支条件指令
		else if (asmData->raw->id >= X86_INS_JAE && asmData->raw->id <= X86_INS_JS) {
            //不是最后一条指令
            if (n != node->addrList.size() - 1) {
                step = BuildJmpImm(data, curaddr, node->addrList[n + 1]);
            }
		}
		else {
			step = glb->translate->oneInstruction(emitter, curaddr);
		}
        if (step) {
			VisitStat& stat(visited[curaddr]); // Mark that we visited this instruction
			stat.size = step;		// Record size of instruction
			//指向最新的节点
			if (emptyflag) {
				oiter = obank.beginDead();
			}
			else {
				++oiter;
			}
			if (oiter != obank.endDead()) {
				stat.seqnum = (*oiter)->getSeqNum();
				data.opMarkStartInstruction(*oiter);
				xrefControlFlow(oiter, startbasic, isfallthru, (FuncCallSpecs*)0);
			}
        }
    }
    
    //判断有没有ret结尾
    ghidra::Address endAddr(glb->getDefaultCodeSpace(), node->addrList[node->addrList.size() - 1]);
    auto itEnd = std::prev(obank.endDead());
    if (itEnd != obank.endDead()) {
        if ((*itEnd)->code() != CPUI_RETURN) {
            BuildVmRet(data, endAddr);
        }
    }
}

void ghidra::Funcdata::startVmpProcessing(void)
{
	if ((flags & processing_started) != 0)
		throw LowlevelError("Function processing already started");
	flags |= processing_started;

	if (funcp.isInline())
		warningHeader("This is an inlined function");
	localmap->clearUnlocked();
	funcp.clearUnlockedOutput();
	Address baddr(baseaddr.getSpace(), 0);
	Address eaddr(baseaddr.getSpace(), ~((uintb)0));
    if (nodeInput) {
        followVmpNode(nodeInput);
    }
    else if (vm_basicblock) {
        followVmpBasicBlock(vm_basicblock);
    }
	else if (vm_func) {
        followVmpFunction(vm_func);
	}
    else {
        followFlow(baddr, eaddr);
    }
	structureReset();
	sortCallSpecs();		// Must come after structure reset
	heritage.buildInfoList();
	localoverride.applyDeadCodeDelay(*this);
}

void ghidra::Funcdata::clearExtensionData()
{
	actIdx = 0x0;
	nodeInput = nullptr;
    vm_basicblock = nullptr;
    vm_func = nullptr;
}

void ghidra::Funcdata::buildReturnVal()
{
    std::vector<VarnodeData> retVarList;
    retVarList.push_back(glb->translate->getRegister("EAX"));
    retVarList.push_back(glb->translate->getRegister("EBX"));
    retVarList.push_back(glb->translate->getRegister("ECX"));
    retVarList.push_back(glb->translate->getRegister("EDX"));
    retVarList.push_back(glb->translate->getRegister("EBP"));
    retVarList.push_back(glb->translate->getRegister("ESP"));
    retVarList.push_back(glb->translate->getRegister("ESI"));
    retVarList.push_back(glb->translate->getRegister("EDI"));
    retVarList.push_back(glb->translate->getRegister("eflags"));
    retVarList.push_back(glb->translate->getRegister("EIP"));
    auto opStart = beginOp(ghidra::CPUI_RETURN);
    auto opEnd = endOp(ghidra::CPUI_RETURN);
    while (opStart != opEnd) {
        ghidra::PcodeOp* retOp = *opStart;
        for (const VarnodeData& retVar : retVarList) {
            ghidra::Varnode* tmpVarNode = newVarnode(retVar.size, retVar.space, retVar.offset);
            opInsertInput(retOp, tmpVarNode, retOp->numInput());
        }
        opStart++;
    }
}

void ghidra::Funcdata::followVmpFunction(VmpFunction* vmFunc)
{
    vm_func = vmFunc;
	if (!obank.empty()) {
		if ((flags & blocks_generated) == 0)
			throw LowlevelError("Function loaded for inlining");
		return;	// Already translated
	}
	uint4 fl = 0;
	fl |= glb->flowoptions;	// Global flow options
	FlowInfo flow(*this, obank, bblocks, qlst);
	flow.setFlags(fl);
	flow.setMaximumInstructions(glb->max_instructions);
	flow.generateVmpFunctionOps(vm_func);
#ifdef DeveloperMode
	std::stringstream ss;
	printRaw(ss);
	std::string rawResult = ss.str();
#endif
	flow.generateBlocks();
	flags |= blocks_generated;
	switchOverJumpTables(flow);
	if (flow.hasUnimplemented())
		flags |= unimplemented_present;
	if (flow.hasBadData())
		flags |= baddata_present;
}

void ghidra::Funcdata::followVmpBasicBlock(VmpBasicBlock* node)
{
    vm_basicblock = node;
	if (!obank.empty()) {
		if ((flags & blocks_generated) == 0)
			throw LowlevelError("Function loaded for inlining");
		return;	// Already translated
	}
	uint4 fl = 0;
	fl |= glb->flowoptions;	// Global flow options
	FlowInfo flow(*this, obank, bblocks, qlst);
	flow.setFlags(fl);
	flow.setMaximumInstructions(glb->max_instructions);
    flow.generateVmpBlockOps(vm_basicblock, true);
	buildReturnVal();
#ifdef DeveloperMode
	std::stringstream ss;
	printRaw(ss);
	std::string rawResult = ss.str();
#endif
	flow.generateBlocks();
	flags |= blocks_generated;
	switchOverJumpTables(flow);
	if (flow.hasUnimplemented())
		flags |= unimplemented_present;
	if (flow.hasBadData())
		flags |= baddata_present;
}

void ghidra::Funcdata::followVmpNode(VmpNode* node)
{
    nodeInput = node;
    if (!obank.empty()) {
        if ((flags & blocks_generated) == 0)
            throw LowlevelError("Function loaded for inlining");
        return;	// Already translated
    }
    uint4 fl = 0;
    fl |= glb->flowoptions;	// Global flow options
    FlowInfo flow(*this, obank, bblocks, qlst);
    flow.setFlags(fl);
    flow.setMaximumInstructions(glb->max_instructions);
    flow.generateVmpNodeOps(node);
    buildReturnVal();
#ifdef _DEBUG
    std::stringstream ss;
    printRaw(ss);
    std::string rawResult = ss.str();
#endif
    flow.generateBlocks();
    flags |= blocks_generated;
    switchOverJumpTables(flow);
    if (flow.hasUnimplemented())
        flags |= unimplemented_present;
    if (flow.hasBadData())
        flags |= baddata_present;
}

ghidra::int4 ghidra::Action::debugApply(Funcdata& data)
{
#ifdef DeveloperMode
    if (data.actIdx == 19) {
        std::stringstream ss;
        data.printRaw(ss);
        std::string rawResult = ss.str();
        int a = 0;
    }
#endif
    ghidra::int4 ret = apply(data);
#ifdef DeveloperMode
    if (count > 0) {
        int a = 0;
    }
    std::string actClassName = typeid(*this).name();
    if (actClassName == "class ghidra::ActionRestartGroup") {
        return ret;
    }
    std::stringstream ss;
    data.printRaw(ss);
    std::string rawResult = ss.str();
    std::string logFilePath = R"(C:\Work\VmpConsole\VmpConsole\Release\log\)";
    logFilePath = logFilePath + std::to_string(data.actIdx++) + "_" + this->getGroup() + "_" + this->getName() + ".txt";
    std::fstream outFile;
    outFile.open(logFilePath, std::ios::out | std::ios::trunc);
    outFile << rawResult;
    outFile.close();
#endif
    return ret;
}

void VmpNode::append(VmpNode& other)
{
    addrList.insert(addrList.end(), other.addrList.begin(), other.addrList.end());
    contextList.insert(contextList.end(), other.contextList.begin(), other.contextList.end());
}

VmAddress VmpNode::readVmAddress(const std::string& reg_code)
{
    VmAddress retaddr;
    if (addrList.empty()) {
        return retaddr;
    }
    retaddr.raw = addrList[0];
    retaddr.vmdata = contextList[0].ReadReg(reg_code);
    return retaddr;
}

size_t VmpNode::findRegContext(size_t eip, const std::string& regName)
{
    for (unsigned int n = 0; n < contextList.size(); ++n) {
        if (contextList[n].EIP == eip) {
            return contextList[n].ReadReg(regName);
        }
    }
    return 0x0;
}

void VmpNode::clear()
{
    addrList.clear();
    contextList.clear();
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif