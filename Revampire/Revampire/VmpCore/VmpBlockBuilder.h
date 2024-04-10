#pragma once
#include "../GhidraExtension/VmpInstruction.h"

namespace GhidraHelper
{
	struct TraceResult;
}

class VmpControlFlowBuilder;
class VmpFlowBuildContext;
class VmpNode;
class VmpBasicBlock;

//处理真vmp基本块

class VmpBlockBuilder
{
public:
	VmpBlockBuilder(VmpControlFlowBuilder& cfg);
	~VmpBlockBuilder() {};
public:
	bool BuildVmpBlock(VmpFlowBuildContext* task);
private:
	bool ExecuteVmpPattern(VmpNode& nodeInput);
	bool Execute_FIND_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd);
	bool Execute_FINISH_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd);


	bool tryMatch_vPopReg(ghidra::PcodeOp* opStore, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult);
	bool tryMatch_vPushImm(ghidra::Funcdata* fd, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult);
	bool tryMatch_vPushReg(ghidra::Funcdata* fd, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult);
	bool tryMatch_vLogicalOp(ghidra::Funcdata* fd, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult);
	bool tryMatch_vCheckEsp(ghidra::Funcdata* fd, VmpNode& nodeInput);
	bool tryMatch_vJmp(ghidra::Funcdata* fd, VmpNode& nodeInput);
private:
	//执行每条op指令
	bool executeVmpOp(std::unique_ptr<VmpInstruction> inst);
private:
	VmpControlFlowBuilder& flow;
	VmpBasicBlock* curBlock;
	VmpFlowBuildContext* buildCtx;
};