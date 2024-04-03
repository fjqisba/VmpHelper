#include "VmpTraceFlowGraph.h"
#include "../Manager/DisasmManager.h"

VmpTraceFlowGraph::VmpTraceFlowGraph()
{

}

VmpTraceFlowGraph::~VmpTraceFlowGraph()
{

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
    return false;
}

void VmpTraceFlowGraph::executeMerge(VmpTraceFlowNode* fatherNode, VmpTraceFlowNode* childNode)
{
    removeEdge(fatherNode->EndAddr(), childNode->nodeEntry);
    //子节点地址移到父节点
    for (unsigned int n = 0; n < childNode->addrList.size(); ++n) {
        fatherNode->addrList.push_back(childNode->addrList[n]);
        updateInstructionToNodeMap(childNode->addrList[n], fatherNode, fatherNode->addrList.size() + n);
    }
}

bool VmpTraceFlowGraph::checkMerge_Vmp300(size_t nodeAddr)
{
    size_t fromAddr = *toEdges[nodeAddr].begin();
    VmpTraceFlowNode* fatherNode = instructionToNodeMap[fromAddr].vmNode;
    //cs_insn* tmpIns = DisasmManager::Main().DecodeInstruction(fatherNode->EndAddr());
    //if (!tmpIns) {
    //    return false;
    //}
    //如果是jmp eax这种指令,不进行合并
    //if (tmpIns->id == X86_INS_JMP && tmpIns->detail->x86.operands[0].type == X86_OP_REG) {
    //    return false;
    //}
    //if (tmpIns->id == X86_INS_RET) {
    //    return false;
    //}
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
            //这一定是出问题了
            throw "error";
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
    //处于相同的区块且符合下一条指令
    if (curNodeIndex->vmNode == nextNodeIndex->vmNode) {
        if (curNodeIndex->index + 1 == nextNodeIndex->index) {
            return true;
        }
        //这个理论上是不可能的
        return false;
    }
    //说明有其它指令分割了A->B,忽略就行了
    return true;
}



//存在一条从地址A执行到地址B的指令
//修正算法是什么样的?
//1、存在两种情况,第一种是从A执行到B,第二种是从A跳到B,这两种逻辑是不一样的
//2、如果是从A执行到B
//先判断A和B的存在情况
//如果A和B都存在,B已是A的下一条指令,则忽略
//如果A和B都存在,B不是A的下一条指令,说明
//To do...
//3、如果是从A跳转到B


bool VmpTraceFlowGraph::addLink(size_t fromAddr, size_t toAddr)
{
    //cs_insn* tmpIns = DisasmManager::Main().DecodeInstruction(fromAddr);
    //if (!tmpIns) {
    //    return false;
    //}
    //if (isEndIns(tmpIns)) {
    //    return addJmpLink(fromAddr, toAddr);
    //}
    //else {
    //    return addNormalLink(fromAddr, toAddr);
    //}
    return true;
}

void VmpTraceFlowGraph::AddTraceFlow(const std::vector<reg_context>& traceList)
{
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
                if (checkMerge_Vmp300(nodeAddr)) {
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
    char addrBuffer[0x10];
    DisasmManager& disasmMgr = DisasmManager::Main();
    for (std::map<size_t, VmpTraceFlowNode>::iterator it = nodeMap.begin(); it != nodeMap.end(); ++it) {
        VmpTraceFlowNode& node = it->second;
        sprintf_s(addrBuffer, sizeof(addrBuffer), "%08X", it->first);
        ss << "\"" << addrBuffer << "\"[label=\"";
        for (unsigned int n = 0; n < node.addrList.size(); ++n) {
            if (bCompress) {
                if (n > 20 && (n != node.addrList.size() - 1)) {
                    continue;
                }
            }
            //cs_insn* tmpIns = disasmMgr.DecodeInstruction(node.addrList[n]);
            sprintf_s(addrBuffer, sizeof(addrBuffer), "%08X", node.addrList[n]);
            //if (tmpIns) {
            //    ss << addrBuffer << "\t" << tmpIns->mnemonic << " " << tmpIns->op_str << "\\n";
            //}
            //else {
            //    ss << addrBuffer << "\t" << "invalid instruction" << "\\n";
            //}
        }
        ss << "\"];\n";
    }

    for (std::map<size_t, std::unordered_set<size_t>>::iterator it = fromEdges.begin(); it != fromEdges.end(); ++it) {
        std::unordered_set<size_t>& edgeList = it->second;
        for (std::unordered_set<size_t>::iterator edegIt = edgeList.begin(); edegIt != edgeList.end(); ++edegIt) {
            VmpTraceFlowNode* fromBlock = instructionToNodeMap[it->first].vmNode;
            sprintf_s(addrBuffer, sizeof(addrBuffer), "%08X", fromBlock->nodeEntry);
            ss << "\"" << addrBuffer << "\" -> ";
            sprintf_s(addrBuffer, sizeof(addrBuffer), "%08X", *edegIt);
            ss << "\"" << addrBuffer << "\";\n";
        }
    }
    ss << "\n}";
    return;
}