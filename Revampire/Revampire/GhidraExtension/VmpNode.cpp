#include "VmpNode.h"
#include "../Ghidra/funcdata.hh"
#include "../Ghidra/flow.hh"
#include "../Ghidra/action.hh"
#include "../Manager/DisasmManager.h"
#include "../GhidraExtension/FuncBuildHelper.h"


void BuildVmRet(ghidra::Funcdata& data, const ghidra::Address& addr)
{
    //return 0x0,第一个参数似乎必须是常量
    ghidra::PcodeOp* opReturn = data.newOp(1, addr);
    data.opSetOpcode(opReturn, ghidra::CPUI_RETURN);
    data.opSetInput(opReturn, data.newConstant(4, 0x0), 0);
    return;
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

int BuildJmpIns(ghidra::Funcdata& data, ghidra::Address& pc, cs_insn* raw)
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

void ghidra::FlowInfo::processVmpInstruction(Address& curaddr, bool& startbasic)
{
    bool emptyflag;
    bool isfallthru = true;
    list<PcodeOp*>::const_iterator oiter;
    int4 step = 0x0;

    //先取出最后一个opcode
    if (obank.empty())
        emptyflag = true;
    else {
        emptyflag = false;
        oiter = obank.endDead();
        --oiter;
    }
    

    //再生成新的opcode
    auto asmData = DisasmManager::Main().DecodeInstruction(curaddr.getOffset());
    if (DisasmManager::IsE8Call(asmData->raw)) {
        step = BuildVmCall(data, curaddr);
    } //jmp eax
    else if (asmData->raw->id == X86_INS_JMP && asmData->raw->detail->x86.operands[0].type == X86_OP_REG) {
        step = BuildJmpIns(data, curaddr, asmData->raw);
    }
    else {
        step = glb->translate->oneInstruction(emitter, curaddr);
    }

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

void ghidra::FlowInfo::generateVmpNodeOps(VmpNode* node)
{
    clearProperties();
    bool startbasic = true;
    for (unsigned int n = 0; n < node->addrList.size(); ++n) {
        ghidra::Address disAddr(glb->getDefaultCodeSpace(), node->addrList[n]);
        processVmpInstruction(disAddr, startbasic);
    }

    //判断有没有ret结尾
    auto itEnd = std::prev(obank.endDead());
    if (itEnd != obank.endDead()) {
        if ((*itEnd)->code() != CPUI_RETURN) {
            BuildVmRet(data, ghidra::Address(glb->getDefaultCodeSpace(), node->addrList[node->addrList.size() - 1]));
        }
    }
}

void ghidra::Funcdata::FollowVmpNode(VmpNode* node)
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
    ghidra::int4 ret = apply(data);
#ifdef _DEBUG
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