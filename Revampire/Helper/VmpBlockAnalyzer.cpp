#include "VmpBlockAnalyzer.h"
#include "../Ghidra/funcdata.hh"
#include "./GhidraHelper.h"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

VmpBlockAnalyzer::VmpBlockAnalyzer()
{

}

z3::expr VmpBlockAnalyzer::EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp)
{
	if (!defOp) {
		return ctx.bv_const("empty", 32);
	}
	switch (defOp->code())
	{
	case ghidra::CPUI_INT_ADD:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) + EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_SUB:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) - EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_COPY:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0));
	case ghidra::CPUI_LOAD:
		//暂时不处理
		break;
	case ghidra::CPUI_INT_AND:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) & EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_OR:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) | EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_NEGATE:
		return ~EvaluateVarnode(ctx, defOp, defOp->getIn(0));
	case ghidra::CPUI_INT_RIGHT:
		return z3::lshr(EvaluateVarnode(ctx, defOp, defOp->getIn(0)), EvaluateVarnode(ctx, defOp, defOp->getIn(1)));
	case ghidra::CPUI_INT_MULT:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) * EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_ZEXT:
	{
		std::string regName = GhidraHelper::GetVarnodeRegName(defOp->getIn(0));
		//临时寄存器
		if (regName.length() == 2) {
			return ctx.bv_const(regName.c_str(), 32);
		}
		break;
	}
		return z3::zext(EvaluateVarnode(ctx, defOp, defOp->getIn(0)),defOp->getOut()->getSize() - defOp->getIn(0)->getSize());
	case ghidra::CPUI_INT_EQUAL:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) == EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	default:
		int a = 0;
		break;
	}
	return ctx.bv_const(defOp->getOpName().c_str(), 32);
}

z3::expr VmpBlockAnalyzer::EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
{
	//定位到原始op
	std::list<ghidra::PcodeOp*>::iterator it = bb->endOp();
	auto itBegin = bb->beginOp();
	while (it != bb->beginOp()) {
		--it;
		ghidra::PcodeOp* curOp = *it;
		if (curOp == op) {
			break;
		}
	}
	while (it != itBegin) {
		--it;
		ghidra::PcodeOp* curOp = *it;
		ghidra::Varnode* vOut = curOp->getOut();
		if (!vOut) {
			continue;
		}
		if (vOut->getSpace() != vn->getSpace()) {
			continue;
		}
		if (vOut->getOffset() != vn->getOffset()) {
			continue;
		}
		return EvaluatePcodeOp(ctx, curOp);
	}
	std::string stackOffset = "stack_" + std::to_string(vn->getOffset());
	return ctx.bv_const(stackOffset.c_str(), vn->getSize());
}

z3::expr VmpBlockAnalyzer::EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
{
	ghidra::PcodeOp* defOp = vn->getDef();
	if (defOp) {
		return EvaluatePcodeOp(ctx, defOp);
	}
	if (vn->isConstant()) {
		return ctx.bv_val(vn->getAddr().getOffset(), 32);
	}
	std::string regName = GhidraHelper::GetVarnodeRegName(vn);
	if (!regName.empty()) {
		if (vn->isInput()) {
			return ctx.bv_const(regName.c_str(), 32);
		}
	}
	if (vn->getSpace()->getName() == "stack") {
		return EvalutaeStackVarnode(ctx, op, vn);
	}
	return ctx.bv_const(0x0, 0x0);
}

std::vector<size_t> VmpBlockAnalyzer::AnaVmpBranchAddr(ghidra::Funcdata* func)
{
	std::vector<size_t> branchList;
	fd = func;
	bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return branchList;
	}
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	if (!retOp) {
		return branchList;
	}
	ghidra::Varnode* vEIP = nullptr;
	for (unsigned int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vn = retOp->getIn(n);
		std::string retRegName = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
		if (retRegName != "EIP") {
			continue;
		}
		vEIP = vn;
		break;
	}
	if (!vEIP) {
		return branchList;
	}
	z3::context ctx;
	z3::expr retExpr = EvaluateVarnode(ctx, retOp, vEIP);
	z3::params params(ctx);
	params.set("bv_not_simpl", true);
	retExpr = retExpr.simplify(params);
	std::string sss = retExpr.to_string();
	if (retExpr.is_const()) {
		branchList.push_back(retExpr.as_uint64());
		return branchList;
	}
	int a = 0;
	return branchList;
}

bool DeepStackFix::FixLoadRam(ghidra::PcodeOp* curOp)
{
	z3::context ctx;
	z3::expr formula = EvaluateVarnode(ctx, curOp, curOp->getIn(1));
	z3::params params(ctx);
	params.set("bv_not_simpl", true);
	formula = formula.simplify(params);
	std::string formulaExpr = formula.to_string();
	if (formula.is_app() && formula.decl().decl_kind() == Z3_OP_BADD) {
		z3::expr arg1 = formula.arg(0);
		z3::expr arg2 = formula.arg(1);
		if (arg1.is_numeral() && arg2.decl().name().str() == "ESP") {
			ghidra::Varnode* newvn = fd->newVarnode(curOp->getOut()->getSize(), fd->getArch()->getStackSpace(), arg1.as_uint64());
			fd->opSetInput(curOp, newvn, 0);
			fd->opRemoveInput(curOp, 1);
			fd->opSetOpcode(curOp, ghidra::CPUI_COPY);
			ghidra::Varnode* refvn = curOp->getOut();
			if (refvn->isSpacebasePlaceholder()) {
				refvn->clearSpacebasePlaceholder();	// Clear the trigger
				ghidra::PcodeOp* placeOp = refvn->loneDescend();
				if (placeOp != (ghidra::PcodeOp*)0) {
					ghidra::FuncCallSpecs* fc = fd->getCallSpecs(placeOp);
					if (fc != (ghidra::FuncCallSpecs*)0)
						fc->resolveSpacebaseRelative(*fd, refvn);
				}
			}
			return true;
		}
	}
	return false;
}

bool DeepStackFix::FixStoreRam(ghidra::PcodeOp* curOp)
{
	z3::context ctx;
	z3::expr formula = EvaluateVarnode(ctx, curOp, curOp->getIn(1));
	std::string ss1 = formula.to_string();
	z3::params params(ctx);
	params.set("bv_not_simpl", true);
	formula = formula.simplify(params);
	std::string ss2 = formula.to_string();
	ghidra::int4 size = curOp->getIn(2)->getSize();
	if (formula.is_app() && formula.decl().decl_kind() == Z3_OP_BADD) {
		z3::expr arg1 = formula.arg(0);
		z3::expr arg2 = formula.arg(1);
		if (arg1.is_numeral() && arg2.decl().name().str() == "ESP") {
			ghidra::Address stackVar(fd->getArch()->getStackSpace(), uint32_t(arg1.as_uint64()));
			fd->newVarnodeOut(size, stackVar, curOp);
			curOp->getOut()->setStackStore();
			fd->opRemoveInput(curOp, 1);
			fd->opRemoveInput(curOp, 0);
			fd->opSetOpcode(curOp, ghidra::CPUI_COPY);
			return true;
		}
	}
	return false;
}

int DeepStackFix::FixAllRam(ghidra::Funcdata* func)
{
	int ret = 0x0;
	fd = func;
	bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return ret;
	}
	//从上往下逐个修复
	bool bFixSuccess = true;
	auto itBeginOp = bb->beginOp();
	while (bFixSuccess) {
		bFixSuccess = false;
		auto itOp = itBeginOp;
		while (itOp != bb->endOp()) {
			ghidra::PcodeOp* curOp = *itOp;
			if (curOp->code() == ghidra::CPUI_STORE) {
				bFixSuccess = FixStoreRam(curOp);
			}
			else if (curOp->code() == ghidra::CPUI_LOAD) {
				bFixSuccess = FixLoadRam(curOp);
			}
			if (bFixSuccess) {
				itBeginOp = itOp;
				ret = 0x1;
				break;
			}
			itOp++;
		}
	}
	return ret;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif