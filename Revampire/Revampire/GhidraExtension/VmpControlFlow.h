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

class mutable_graph_t;
class VmpFunction;
class VmpControlFlow;
class VmpArchitecture;

struct VmAddress
{
	size_t raw;
	size_t vmdata;
	VmAddress() {
		raw = 0x0;
		vmdata = 0x0;
	}
	VmAddress(size_t ins, size_t vm) {
		raw = ins;
		vmdata = vm;
	}
	VmAddress(size_t ins) {
		raw = ins;
		vmdata = 0x0;
	}
	bool operator<(const VmAddress& other) const
	{
		return std::tie(raw, vmdata) < std::tie(other.raw, other.vmdata);
	}
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
private:
	VmpUnicorn unicorn;
	VmpTraceFlowGraph& tfg;
	//当前执行的指令顺序
	size_t idx = 0x0;
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


class VmpControlFlowBuilder
{
public:
	enum AnaTaskType {
		TASK_DEFAULT = 0x0,
		FIND_VM_ENTRY,
		HANDLE_VM_ENTRY,
	};
	struct AnaTask
	{
		AnaTaskType type;
		VmAddress vmAddr;
		std::unique_ptr<VmpUnicornContext> ctx;
	};
public:
	VmpControlFlowBuilder(VmpFunction& fd);
	~VmpControlFlowBuilder();
	bool BuildCFG(size_t startAddr);
private:
	VmpArchitecture* Architecture();
	bool fallthruVmp(AnaTask& task);
	void fallthruNormal(AnaTask& task);
	bool isVmpEntry(size_t startAddr);
	VmpBasicBlock* createNewBlock(size_t startAddr);
	void linkBlockEdge(VmAddress from, VmAddress to);
private:
	std::queue<std::unique_ptr<AnaTask>> anaQueue;
	std::set<VmAddress> visited;
	std::map<VmAddress, VmpBasicBlock*> instructionMap;
	std::map<VmAddress, std::set<VmAddress>> fromEdges;
	VmpFunction& data;
	VmpTraceFlowGraph tfg;
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
	std::unordered_map<size_t, VmpBasicBlock> blocksMap;
};