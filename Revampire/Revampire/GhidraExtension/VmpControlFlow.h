#pragma once
#include <map>
#include <queue>
#include <memory>
#include <set>
#include <unordered_map>
#include "../Helper/UnicornHelper.h"
#include "../Manager/DisasmManager.h"
#include "../VmpCore/VmpTraceFlowGraph.h"
#include "../VmpCore/VmpUnicorn.h"
#include "../GhidraExtension/VmpNode.h"
#include "../GhidraExtension/VmpInstruction.h"
#include "../Common/VmpCommon.h"

class mutable_graph_t;
class VmpFunction;
class VmpControlFlow;
class VmpArchitecture;
class VmpBasicBlock;

class VmpRegStatus
{
public:
	void ClearStatus();
	//vm字节码寄存器
	std::string reg_code;
	//vm虚拟堆栈寄存器
	std::string reg_stack;
	//是否已选择好了寄存器
	bool isSelected = false;
};

class VmpFlowBuildContext
{
public:
	enum FlowBuildType {
		HANDLE_NORMAL = 0x0,
		HANDLE_VMP_ENTRY,
		HANDLE_VMP_JMP,
	};
	enum VM_MATCH_STATUS {
		FIND_VM_INIT = 0x0,
		FINISH_VM_INIT = 0x1,
	};
public:
	VmpFlowBuildContext();
public:
	FlowBuildType btype;
	//起始地址
	VmAddress start_addr;
	//vm寄存器状态
	VmpRegStatus vmreg;
	//模拟执行状态
	std::unique_ptr<VmpUnicornContext> ctx;


	VM_MATCH_STATUS status;
	//记录上一个block
	VmAddress from_addr;
};

class VmpControlFlowBuilder
{
	friend class VmpBlockBuilder;
public:
	VmpControlFlowBuilder(VmpFunction& fd);
	~VmpControlFlowBuilder();
	bool BuildCFG(size_t startAddr);
protected:
	VmpBasicBlock* createNewBlock(VmAddress startAddr);
private:
	void addVmpEntryBuildTask(VmAddress startAddr);
	VmpArchitecture* Arch();
	void fallthruVmp(VmpFlowBuildContext& task);
	void fallthruNormal(VmpFlowBuildContext& task);
	bool isVmpEntry(size_t startAddr);
	void linkBlockEdge(VmAddress from, VmAddress to);
public:
	VmpTraceFlowGraph tfg;
private:
	std::queue<std::unique_ptr<VmpFlowBuildContext>> anaQueue;
	std::set<VmAddress> visited;
	std::map<VmAddress, VmpBasicBlock*> instructionMap;
	std::map<VmAddress, std::set<VmAddress>> fromEdges;
	VmpFunction& data;
};


class VmpBlockWalker
{
public:
	VmpBlockWalker(VmpTraceFlowGraph& t) :tfg(t) {};
	~VmpBlockWalker() {};
public:
	void StartWalk(VmpUnicornContext& startCtx, size_t walkSize);
	const std::vector<reg_context>& GetTraceList();
	bool IsWalkToEnd();
	VmpNode GetNextNode();
	void MoveToNext();
private:
	VmpUnicorn unicorn;
	VmpTraceFlowGraph& tfg;
	//当前执行的指令顺序
	size_t idx = 0x0;
	//当前节点大小
	size_t curNodeSize = 0x0;
};

class VmpBasicBlock
{
public:
	//和IDA打印图有关
	void SetGraphIndex(int idx) { graphIdx = idx; };
	int GetGraphIndex() { return graphIdx; };
	std::string MakeGraphTxt();
public:
	std::vector<std::unique_ptr<vm_inst>> insList;
	std::vector<VmpBasicBlock*> inBlocks;
	std::vector<VmpBasicBlock*> outBlocks;
	VmAddress blockEntry;
private:
	int graphIdx = 0x0;
};




//仅用于进行IDA展示

class VmpControlFlowShowGraph
{
public:
	VmpControlFlowShowGraph(VmpControlFlow* c) { cfg = c; };
	~VmpControlFlowShowGraph() {};
	static ptrdiff_t __stdcall graph_callback(void* ud, int code, va_list va);
	void refresh_graph(mutable_graph_t* g);
	void gen_graph_text(mutable_graph_t* g);
public:
	std::vector<VmpBasicBlock*> nodesList;
	std::vector<std::string> txtList;
public:
	VmpControlFlow* cfg;
};

class VmpControlFlow
{
	friend class VmpControlFlowBuilder;
public:
	VmpControlFlow();
	~VmpControlFlow();
protected:
	VmpBasicBlock* startBlock;
public:
	VmpControlFlowShowGraph graph;
	//存储所有的block
	std::map<VmAddress, VmpBasicBlock> blocksMap;
};