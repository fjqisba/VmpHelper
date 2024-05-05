#pragma once
#include <vector>
#include <map>
#include <z3++.h>

namespace ghidra
{
	class Funcdata;
	class Varnode;
	class PcodeOp;
	class BlockBasic;
}

struct VmpRotateContext;

class DeepStackFix
{
public:
	int FixAllRam(ghidra::Funcdata* fd);
private:
	bool FixStoreRam(ghidra::PcodeOp* curOp);
	bool FixLoadRam(ghidra::PcodeOp* curOp);
	z3::expr EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
	z3::expr EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp);
	z3::expr EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
protected:
	ghidra::Funcdata* fd = nullptr;
	ghidra::BlockBasic* bb = nullptr;
};

class RotateContextAnalyzer
{
public:
	RotateContextAnalyzer(ghidra::Funcdata* func) {
		fd = func;
	};
	bool UpdateRotateContext(VmpRotateContext& old_ctx, VmpRotateContext& new_ctx);
private:
	bool getEndStackOffset(int& outOffset);
	z3::expr EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
	z3::expr EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp);
	z3::expr EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
private:
	VmpRotateContext* oldCtx = nullptr;
	ghidra::Funcdata* fd = nullptr;
	ghidra::BlockBasic* bb = nullptr;
};

class VmpBranchAnalyzer
{
public:
	VmpBranchAnalyzer(ghidra::Funcdata* func) {
		fd = func;
	};
	std::vector<size_t> GuessVmpBranch();
private:
	std::vector<size_t> guessConditionalBranch(z3::expr& expr);
private:
	z3::expr EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp);
	z3::expr EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
	z3::expr EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
private:
	ghidra::Funcdata* fd = nullptr;
	ghidra::BlockBasic* bb = nullptr;
};