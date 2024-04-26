#pragma once
#include <vector>
#include <z3++.h>

namespace ghidra
{
	class Funcdata;
	class Varnode;
	class PcodeOp;
	class BlockBasic;
}

class VmpBlockAnalyzer
{
public:
	VmpBlockAnalyzer();
	std::vector<size_t> AnaVmpBranchAddr(ghidra::Funcdata* fd);
protected:
	z3::expr EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
	z3::expr EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp);
	z3::expr EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn);
protected:
	ghidra::Funcdata* fd = nullptr;
	ghidra::BlockBasic* bb = nullptr;
};

class DeepStackFix:public VmpBlockAnalyzer
{
public:
	int FixAllRam(ghidra::Funcdata* fd);
private:
	bool FixStoreRam(ghidra::PcodeOp* curOp);
	bool FixLoadRam(ghidra::PcodeOp* curOp);
};