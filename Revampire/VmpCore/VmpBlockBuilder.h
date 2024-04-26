#pragma once
#include "../GhidraExtension/VmpInstruction.h"
#include "../Helper/UnicornHelper.h"
#include "../VmpCore/VmpUnicorn.h"

namespace GhidraHelper
{
	struct TraceResult;
}

class VmpControlFlowBuilder;
class VmpFlowBuildContext;
class VmpNode;
class VmpBasicBlock;
class VmpTraceFlowGraph;
class VmpOpJmp;
class VmpOpJmpConst;

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
	size_t CurrentIndex();
private:
	VmpUnicorn unicorn;
	VmpTraceFlowGraph& tfg;
	//当前执行的指令顺序
	size_t idx = 0x0;
	//当前节点大小
	size_t curNodeSize = 0x0;
};

//处理真vmp基本块

class VmpBlockBuilder
{
public:
	VmpBlockBuilder(VmpControlFlowBuilder& cfg);
	~VmpBlockBuilder() {};
public:
	bool BuildVmpBlock(VmpFlowBuildContext* task);
private:
	bool Execute_FIND_VM_INIT();
	bool Execute_FINISH_VM_INIT();

	bool tryMatch_vPopReg(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vCpuid(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vPushImm(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vPushReg(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vLogicalOp(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vShrd(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vMemAccess(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vCheckEsp(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vJunkCode(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vJmp(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_Mul(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vExit(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vPushVsp(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vWriteVsp(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vJmpConst(ghidra::Funcdata* fd, VmpNode& nodeInput);
private:
	bool updateVmRegOffset(ghidra::Funcdata* fd);
	//执行每条op指令
	bool executeVmpOp(VmpNode& nodeInput, std::unique_ptr<VmpInstruction> inst);
	bool executeVmJmp(VmpNode& nodeInput, VmpOpJmp* inst);
	bool executeVmJmpConst(VmpNode& nodeInput, VmpOpJmpConst* inst);
	bool executeVmInit(VmpNode& nodeInput, VmpInstruction* inst);
	bool executeVmExit(VmpNode& nodeInput, VmpInstruction* inst);
	void updateSaveRegContext(ghidra::Funcdata* fd);
public:
	static int vmRegStartAddr;
private:
	VmpControlFlowBuilder& flow;
	VmpBasicBlock* curBlock;
	VmpFlowBuildContext* buildCtx;
	VmpBlockWalker walker;
};