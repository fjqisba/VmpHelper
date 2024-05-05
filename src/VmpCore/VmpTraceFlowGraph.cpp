#include "VmpTraceFlowGraph.h"
#include <sstream>
#include "../Manager/DisasmManager.h"
#include "../Manager/VmpVersionManager.h"
#include "../Manager/exceptions.h"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

VmpTraceFlowGraph::VmpTraceFlowGraph()
{
#ifdef DEBUG_TRACEFLOW
	std::string logFilePath = R"(C:\Work\VmpConsole\VmpConsole\Release\traceflow\flow.txt)";
    logFile.open(logFilePath, std::ios::out | std::ios::trunc);
#endif
}

VmpTraceFlowGraph::~VmpTraceFlowGraph()
{
#ifdef DEBUG_TRACEFLOW
    logFile.close();
#endif
}

bool isEndIns(cs_insn* curIns)
{
    if (curIns->id == x86_insn::X86_INS_RET) {
        return true;
    }
    if (curIns->id == x86_insn::X86_INS_CALL) {
        return true;
    }
    //跳转指令
    if (curIns->id >= x86_insn::X86_INS_JAE && curIns->id <= X86_INS_JS) {
        return true;
    }
    if (curIns->id == x86_insn::X86_INS_JMP) {
        return true;
    }
    return false;
}

void VmpTraceFlowGraph::executeMerge(VmpTraceFlowNode* fatherNode, VmpTraceFlowNode* childNode)
{
    removeEdge(fatherNode->EndAddr(), childNode->nodeEntry);
    //子节点地址移到父节点
    int startIdx = fatherNode->addrList.size();
    for (unsigned int n = 0; n < childNode->addrList.size(); ++n) {
        fatherNode->addrList.push_back(childNode->addrList[n]);
		updateInstructionToNodeMap(childNode->addrList[n], fatherNode, startIdx + n);
    }
}

bool VmpTraceFlowGraph::checkCanMerge_Vmp(size_t nodeAddr)
{
    size_t fromAddr = *toEdges[nodeAddr].begin();
    VmpTraceFlowNode* fatherNode = instructionToNodeMap[fromAddr].vmNode;
    std::unique_ptr<RawInstruction> endIns = DisasmManager::Main().DecodeInstruction(fatherNode->EndAddr());
    if (!endIns) {
        return false;
    }
    //ret指令一般是不进行合并的
    if (endIns->raw->id == X86_INS_RET) {
        return false;
    }
    if (VmpVersionManager::CurrentVmpVersion() == VmpVersionManager::VMP_350) {
        //如果是jmp eax这种指令,不进行合并
        if (endIns->raw->id == X86_INS_JMP && endIns->raw->detail->x86.operands[0].type == X86_OP_REG) {
            return false;
        }
    }
    else if (VmpVersionManager::CurrentVmpVersion() == VmpVersionManager::VMP_380) {
        //jmp eax
        if (endIns->raw->id == X86_INS_JMP && endIns->raw->detail->x86.operands[0].type == X86_OP_REG) {
            if (fatherNode->addrList.size() > 2) {
                x86_reg jmpReg = endIns->raw->detail->x86.operands[0].reg;
                std::unique_ptr<RawInstruction> lastIns = DisasmManager::Main().DecodeInstruction(fatherNode->addrList[fatherNode->addrList.size() - 2]);
                if (lastIns->raw->id == X86_INS_ADC || lastIns->raw->id == X86_INS_ADD) {
                    cs_x86_op& op0 = lastIns->raw->detail->x86.operands[0];
                    cs_x86_op& op1 = lastIns->raw->detail->x86.operands[1];
                    if (op0.type == X86_OP_REG && op1.type == X86_OP_IMM && jmpReg == op0.reg) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
    return true;
}


bool VmpTraceFlowGraph::checkCanMerge(size_t nodeAddr)
{
    //条件1,指向子节点的边只有1条
    if (toEdges[nodeAddr].size() != 1) {
        return false;
    }
    //拿到指向该节点的父节点
    size_t fromAddr = *toEdges[nodeAddr].begin();
    VmpTraceFlowNode* fatherNode = instructionToNodeMap[fromAddr].vmNode;
    //条件2,父节点指向的边也只有1条
    if (fromEdges[fromAddr].size() != 1) {
        return false;
    }
    //条件3,子节点不能指向父节点
    if (fromEdges[nodeAddr].count(fatherNode->addrList[fatherNode->addrList.size() - 1])) {
        return false;
    }
    return true;
}

VmpTraceFlowNode* VmpTraceFlowGraph::splitBlock(VmpTraceFlowNode* toNode, size_t splitAddr)
{
    VmpTraceFlowNode* newNode = createNode(splitAddr);
    unsigned int index = 1;
    while (true) {
        if (index >= toNode->addrList.size()) {
            throw VmpTraceException("splitBlock error");
        }
        if (toNode->addrList[index] == splitAddr) {
            linkEdge(toNode->addrList[index - 1], splitAddr);
            break;
        }
        index++;
    }
    //立即更新指令表
    int insIndex = 1;
    for (unsigned int n = index + 1; n < toNode->addrList.size(); ++n) {
        newNode->addrList.push_back(toNode->addrList[n]);
        this->updateInstructionToNodeMap(toNode->addrList[n], newNode, insIndex++);
    }
    //截取上半段Block
    toNode->addrList.resize(index);
    return newNode;
}

VmpTraceFlowNode* VmpTraceFlowGraph::createNode(size_t start)
{
    VmpTraceFlowNode* newNode = &nodeMap[start];
    newNode->nodeEntry = start;
    newNode->addrList.push_back(start);
    this->updateInstructionToNodeMap(start, newNode, 0x0);
    return newNode;
}

void VmpTraceFlowGraph::removeEdge(size_t from, size_t to)
{
    fromEdges[from].erase(to);
    toEdges[to].erase(from);
}

void VmpTraceFlowGraph::linkEdge(size_t from, size_t to)
{
    fromEdges[from].insert(to);
    toEdges[to].insert(from);
}

void VmpTraceFlowGraph::updateInstructionToNodeMap(size_t addr, VmpTraceFlowNode* updateNode, int index)
{
    this->instructionToNodeMap[addr] = VmpTraceFlowNodeIndex(updateNode, index);
}

bool VmpTraceFlowGraph::addJmpLink(size_t fromAddr, size_t toAddr)
{
#ifdef DEBUG_TRACEFLOW
	logFile << "Jmp from " << std::hex << fromAddr << " - " << toAddr << std::endl;
    if (toAddr == 0x451cef) {
        int a = 0;
    }
#endif
    linkEdge(fromAddr, toAddr);
    //先确保存在两个区块
    VmpTraceFlowNodeIndex* curNodeIndex = &instructionToNodeMap[fromAddr];
    if (curNodeIndex->vmNode == nullptr) {
        curNodeIndex->vmNode = createNode(fromAddr);
        curNodeIndex->index = 0x0;
    }
    VmpTraceFlowNodeIndex* nextNodeIndex = &instructionToNodeMap[toAddr];
    if (nextNodeIndex->vmNode == nullptr) {
        nextNodeIndex->vmNode = createNode(toAddr);
        nextNodeIndex->index = 0x0;
    }
    //只有当from是区块尾地址且to位于区块首地址才不用分块
    if (curNodeIndex->index == curNodeIndex->vmNode->addrList.size() - 1 && nextNodeIndex->index == 0x0) {
        return true;
    }
    //确定需要分块
    //二者已经在同一个区块内了
    if (curNodeIndex->vmNode == nextNodeIndex->vmNode) {
        splitBlock(nextNodeIndex->vmNode, toAddr);
        return true;
    }
    //二者在不同的区块
    if (curNodeIndex->index != curNodeIndex->vmNode->addrList.size() - 1) {
        splitBlock(curNodeIndex->vmNode, fromAddr);
    }
    if (nextNodeIndex->index != 0x0) {
        splitBlock(nextNodeIndex->vmNode, toAddr);
    }
    return true;
}

bool VmpTraceFlowGraph::addNormalLink(size_t fromAddr, size_t toAddr)
{
#ifdef DEBUG_TRACEFLOW
    logFile << "link from " << std::hex << fromAddr << " - " << toAddr << std::endl;
    if (fromAddr == 0x451CEF) {
        int a = 0;
    }
#endif
    VmpTraceFlowNodeIndex* curNodeIndex = &instructionToNodeMap[fromAddr];
    if (curNodeIndex->vmNode == nullptr) {
        curNodeIndex->vmNode = createNode(fromAddr);
        curNodeIndex->index = 0x0;
    }
    VmpTraceFlowNodeIndex* nextNodeIndex = &instructionToNodeMap[toAddr];
    if (nextNodeIndex->vmNode == nullptr) {
        curNodeIndex->vmNode->addrList.push_back(toAddr);
        nextNodeIndex->vmNode = curNodeIndex->vmNode;
        nextNodeIndex->index = curNodeIndex->index + 1;
    }
    //处于相同的区块且符合跳转顺序
    if (curNodeIndex->vmNode == nextNodeIndex->vmNode) {
        if (curNodeIndex->index + 1 == nextNodeIndex->index) {
            return true;
        }
        //这个理论上是不可能的
        throw VmpTraceException("addNormalLink error");
    }
    //说明有其它指令分割了A->B,忽略就行了
    return true;
}

bool VmpTraceFlowGraph::addLink(size_t fromAddr, size_t toAddr)
{
    std::unique_ptr<RawInstruction> tmpIns = DisasmManager::Main().DecodeInstruction(fromAddr);
    if (!tmpIns) {
        return false;
    }
    //将问题简化为两种情况
    //第一种是从A执行到B,第二种是从A跳到B
    if (isEndIns(tmpIns->raw)) {
        return addJmpLink(fromAddr, toAddr);
    }
    else {
        return addNormalLink(fromAddr, toAddr);
    }
    return true;
}

void VmpTraceFlowGraph::AddTraceFlow(const std::vector<reg_context>& traceList)
{
    if (traceList.size() <= 1) {
        return;
    }
    for (unsigned int n = 0; n < traceList.size() - 1; n++) {
        if (!addLink(traceList[n].EIP, traceList[n + 1].EIP)) {
            return;
        }
    }
}

void VmpTraceFlowGraph::MergeAllNodes()
{
    //已确定无法合并的节点
    std::set<size_t> badNodeList;
    bool bUpdateNode;
    do
    {
        bUpdateNode = false;
        std::map<size_t, VmpTraceFlowNode>::iterator it = nodeMap.begin();
        while (it != nodeMap.end()) {
            size_t nodeAddr = it->first;
            if (badNodeList.count(nodeAddr)) {
                it++;
                continue;
            }
            if (checkCanMerge(nodeAddr)) {
                size_t fromAddr = *toEdges[nodeAddr].begin();
                VmpTraceFlowNode* fatherNode = instructionToNodeMap[fromAddr].vmNode;
                if (checkCanMerge_Vmp(nodeAddr)) {
                    executeMerge(fatherNode, &it->second);
                    bUpdateNode = true;
                    it = nodeMap.erase(it);
                    continue;
                }
            }
            badNodeList.insert(nodeAddr);
            it++;
        }
    } while (bUpdateNode);
}

void VmpTraceFlowGraph::DumpGraph(std::ostream& ss, bool bCompress)
{
    ss << "strict digraph \"hello world\"{\n";
    for (std::map<size_t, VmpTraceFlowNode>::iterator it = nodeMap.begin(); it != nodeMap.end(); ++it) {
        VmpTraceFlowNode& node = it->second;
        ss << "\"" << std::hex << it->first << "\"[label=\"";
        for (unsigned int n = 0; n < node.addrList.size(); ++n) {
            if (bCompress) {
                if (n > 20 && (n != node.addrList.size() - 1)) {
                    continue;
                }
            }
            std::unique_ptr<RawInstruction> tmpIns = DisasmManager::Main().DecodeInstruction(node.addrList[n]);
            if (tmpIns) {
                ss << std::hex << node.addrList[n] << "\t" << tmpIns->raw->mnemonic << " " << tmpIns->raw->op_str << "\\n";
            }
            else {
                ss << std::hex << node.addrList[n] << "\t" << "invalid instruction" << "\\n";
            }
        }
        ss << "\"];\n";
    }
    for (std::map<size_t, std::unordered_set<size_t>>::iterator it = fromEdges.begin(); it != fromEdges.end(); ++it) {
        std::unordered_set<size_t>& edgeList = it->second;
        for (std::unordered_set<size_t>::iterator edegIt = edgeList.begin(); edegIt != edgeList.end(); ++edegIt) {
            VmpTraceFlowNode* fromBlock = instructionToNodeMap[it->first].vmNode;
            ss << "\"" << std::hex << fromBlock->nodeEntry << "\" -> ";
            ss << "\"" << std::hex << *edegIt << "\";\n";
        }
    }
    ss << "\n}";
    return;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif