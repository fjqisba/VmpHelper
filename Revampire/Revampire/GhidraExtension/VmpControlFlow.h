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
		FINISH_VM_INIT,
		//寻找vm寄存器
		FIND_VM_REG,
		//完成匹配
		FINISH_MATCH,
		MATCH_ERROR,
	};
public:
	VmpFlowBuildContext();
public:
	FlowBuildType btype;
	//起始地址
	VmAddress start_addr;
	//vm寄存器状态
	VmpRegStatus vmreg;
	//模拟数据
	std::unique_ptr<VmpUnicornContext> ctx;
	//记录来源地址
	VmAddress from_addr;
	//模拟状态
	VM_MATCH_STATUS status;
};

class VmpControlFlowBuilder
{
	friend class VmpBlockBuilder;
public:
	VmpControlFlowBuilder(VmpFunction& fd);
	~VmpControlFlowBuilder();
	bool BuildCFG(size_t startAddr);
protected:
	VmpBasicBlock* createNewBlock(VmAddress startAddr,bool isVmBlock);
	void addVmpEntryBuildTask(VmAddress startAddr);
	void addNormalBuildTask(VmAddress startAddr);
private:
	VmpArchitecture* Arch();
	void fallthruVmp(VmpFlowBuildContext& task);
	void fallthruNormal(VmpFlowBuildContext& task);
	void linkBlockEdge(VmAddress from, VmAddress to);
	void buildEdges();
	void buildJmps();
public:
	VmpTraceFlowGraph tfg;
protected:
	std::queue<std::unique_ptr<VmpFlowBuildContext>> anaQueue;
private:
	std::set<VmAddress> visited;
	std::map<VmAddress, VmpBasicBlock*> instructionMap;
	std::map<VmAddress, std::set<VmAddress>> fromEdges;
	VmpFunction& data;
};

class VmpBasicBlock
{
	enum {
		start_block = 0x1,
		end_block = 0x2,
		vm_ins_block = 0x4,
	};
public:
	//和IDA打印图有关
	void SetGraphIndex(int idx) { graphIdx = idx; };
	int GetGraphIndex() { return graphIdx; };
	std::string MakeGraphTxt();

	void setEndBlock() { flags |= end_block; };
	bool isEndBlock() { return ((flags & end_block) != 0); };
	void setStartBlock() { flags |= start_block; };
	bool isStartBlock() { return ((flags & start_block) != 0); };
	void setVmInsBlock() { flags |= vm_ins_block; };
	bool isVmInsBlock() { return ((flags & vm_ins_block) != 0); };
public:
	std::vector<std::unique_ptr<vm_inst>> insList;
	std::vector<VmpBasicBlock*> inBlocks;
	std::vector<VmpBasicBlock*> outBlocks;
	VmAddress blockEntry;
private:
	int graphIdx = 0x0;
	unsigned int flags;
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
	VmpBasicBlock* StartBlock() { return startBlock; };
protected:
	VmpBasicBlock* startBlock;
public:
	VmpControlFlowShowGraph graph;
	//存储所有的block
	std::map<VmAddress, VmpBasicBlock> blocksMap;
};