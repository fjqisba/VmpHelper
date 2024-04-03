#pragma once
#include <vector>
#include <map>
#include <sstream>
#include <set>
#include <unordered_set>
#include "../Helper/UnicornHelper.h"

struct VmpTraceFlowNode
{
public:
    //基本块入口
    size_t nodeEntry;
    //指令列表
    std::vector<size_t> addrList;
    VmpTraceFlowNode() {
        nodeEntry = 0x0;
    }
public:
    size_t TryGetAddr(size_t index) {
        if (index >= addrList.size()) {
            return 0x0;
        }
        return addrList[index];
    }
    size_t EndAddr() {
        return addrList[addrList.size() - 1];
    }
};

struct VmpTraceFlowNodeIndex
{
    VmpTraceFlowNode* vmNode;
    int index;
    VmpTraceFlowNodeIndex() {
        vmNode = nullptr;
        index = -1;
    }
    VmpTraceFlowNodeIndex(VmpTraceFlowNode* node, int idx) {
        vmNode = node;
        index = idx;
    }
};

class VmpTraceFlowGraph
{
public:
    VmpTraceFlowGraph();
    ~VmpTraceFlowGraph();
public:
    void AddTraceFlow(const std::vector<reg_context>& traceList);
    void DumpGraph(std::ostream& ss, bool bCompress);
    //对节点进行合并优化
    void MergeAllNodes();
private:
    void updateInstructionToNodeMap(size_t addr, VmpTraceFlowNode* updateNode, int index);
    bool addLink(size_t fromAddr, size_t toAddr);
    bool addNormalLink(size_t fromAddr, size_t toAddr);
    bool addJmpLink(size_t fromAddr, size_t toAddr);
    void removeEdge(size_t from, size_t to);
    void linkEdge(size_t from, size_t to);
    VmpTraceFlowNode* createNode(size_t start);
    VmpTraceFlowNode* splitBlock(VmpTraceFlowNode* toNode, size_t splitAddr);
    //是否可以合并
    bool checkCanMerge(size_t nodeAddr);
    bool checkMerge_Vmp300(size_t nodeAddr);
    //执行合并逻辑
    void executeMerge(VmpTraceFlowNode* fatherNode, VmpTraceFlowNode* childNode);
public:
    //key是block的起始地址,value是BasicBlock
    std::map<size_t, VmpTraceFlowNode> nodeMap;
    //key是指令的地址,value是指向Block和所在Block的索引
    std::map<size_t, VmpTraceFlowNodeIndex> instructionToNodeMap;
    //key是连接指令地址,value是被连接指令地址
    std::map<size_t, std::unordered_set<size_t>> fromEdges;
    std::map<size_t, std::unordered_set<size_t>> toEdges;
};