#include "VmpBlockAnalyzer.h"
#include "../Ghidra/funcdata.hh"
#include "./GhidraHelper.h"
#include "../Manager/exceptions.h"
#include "../VmpCore/VmpBlockBuilder.h"
#include "../GhidraExtension/VmpControlFlow.h"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

z3::expr DeepStackFix::EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp)
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
		break;
	case ghidra::CPUI_INT_AND:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) & EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_OR:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) | EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_NEGATE:
		return ~EvaluateVarnode(ctx, defOp, defOp->getIn(0));
	case ghidra::CPUI_INT_MULT:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) * EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	default:
		break;
	}
	throw Exception("bad defcode");
}

z3::expr DeepStackFix::EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
		if(vOut->getSize() != vn->getSize()){
			//To do...
		}
		return EvaluatePcodeOp(ctx, curOp);
	}
	throw Exception("bad stack varnode");
}

z3::expr DeepStackFix::EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
	throw Exception("bad varnode");
}


bool DeepStackFix::FixLoadRam(ghidra::PcodeOp* curOp)
{
	z3::context ctx;
	z3::expr formula(ctx);
	try{
		formula = EvaluateVarnode(ctx, curOp, curOp->getIn(1));
	}
	catch(Exception& ex){
		return false;
	}
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
	else if (formula.is_const() && formula.decl().name().str() == "ESP") {
		ghidra::Varnode* newvn = fd->newVarnode(curOp->getOut()->getSize(), fd->getArch()->getStackSpace(), 0x0);
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
	}
	return false;
}

bool DeepStackFix::FixStoreRam(ghidra::PcodeOp* curOp)
{
	z3::context ctx;
	z3::expr formula(ctx);
	try{
		formula = EvaluateVarnode(ctx, curOp, curOp->getIn(1));
	}
	catch (Exception& ex){
		return false;
	}
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
	else if (formula.is_const() && formula.decl().name().str() == "ESP") {
		ghidra::Address stackVar(fd->getArch()->getStackSpace(), 0x0);
		fd->newVarnodeOut(size, stackVar, curOp);
		curOp->getOut()->setStackStore();
		fd->opRemoveInput(curOp, 1);
		fd->opRemoveInput(curOp, 0);
		fd->opSetOpcode(curOp, ghidra::CPUI_COPY);
		return true;
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
	auto itEndOp = bb->endOp();
	while (bFixSuccess) {
		bFixSuccess = false;
		auto itOp = itBeginOp;
		while (itOp != itEndOp) {
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


z3::expr RotateContextAnalyzer::EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp)
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
	case ghidra::CPUI_INT_AND:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) & EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_OR:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) | EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_NEGATE:
		return ~EvaluateVarnode(ctx, defOp, defOp->getIn(0));
	case ghidra::CPUI_INT_MULT:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) * EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	default:
		break;
	}
	throw Exception("bad defcode");
}

z3::expr RotateContextAnalyzer::EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
	throw Exception("bad varnode");
}

z3::expr RotateContextAnalyzer::EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
	int stackOffset = vn->getOffset();
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
		int newStackOffset = vOut->getOffset();
		if (newStackOffset > stackOffset && newStackOffset - stackOffset < 4) {
			throw Exception("bad assign");
		}
		if (newStackOffset != stackOffset) {
			continue;
		}
		if (vOut->getSize() != vn->getSize()) {
			throw Exception("bad assign");
		}
		return EvaluatePcodeOp(ctx, curOp);
	}
	if (vn->getSize() != 4) {
		throw Exception("bad stack varnode src");
	}
	if (stackOffset % 4) {
		throw Exception("bad stack varnode src");
	}
	int idx = stackOffset / 4;
	auto itSrc = oldCtx->contextMap.find(idx);
	if (itSrc == oldCtx->contextMap.end()) {
		throw Exception("bad stack varnode src");
	}
	if (itSrc->second.space->getName() == "const") {
		return ctx.bv_val(itSrc->second.offset, 32);
	}
	std::string regName = fd->getArch()->translate->getRegisterName(itSrc->second.space, itSrc->second.offset, itSrc->second.size);
	if (!regName.empty()) {
		return ctx.bv_const(regName.c_str(), 32);
	}
	throw Exception("bad stack varnode src");
}

bool RotateContextAnalyzer::getEndStackOffset(int& outOffset)
{
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	if (!retOp) {
		return false;
	}
	for (unsigned int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vn = retOp->getIn(n);
		std::string retRegName = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
		if (retRegName != "ESP") {
			continue;
		}
		ghidra::PcodeOp* defOp = vn->getDef();
		if (!defOp) {
			continue;
		}
		if (defOp->code() == ghidra::CPUI_COPY) {
			ghidra::Varnode* vn = defOp->getIn(0);
			std::string regName = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
			if (vn->isInput() && regName == "ESP") {
				outOffset = 0x0;
				return true;
			}
		}
		else if (defOp->code() == ghidra::CPUI_INT_ADD) {
			ghidra::Varnode* v0 = defOp->getIn(0);
			ghidra::Varnode* v1 = defOp->getIn(1);
			std::string regName = fd->getArch()->translate->getRegisterName(v0->getSpace(), v0->getOffset(), v0->getSize());
			if (v0->isInput() && regName == "ESP" && v1->isConstant()) {
				outOffset = v1->getOffset();
				return true;
			}
		}
	}
	return false;
}

bool RotateContextAnalyzer::UpdateRotateContext(VmpRotateContext& rotate_ctx, VmpRotateContext& out_ctx)
{
	oldCtx = &rotate_ctx;
	bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return false;
	}
	int endStackOffset;
	if (!getEndStackOffset(endStackOffset)) {
		return false;
	}
	std::set<int> visited;
	std::set<std::string> basicReg;
	auto itEnd = bb->endOp();
	auto itBegin = bb->beginOp();
	while (itEnd != itBegin) {
		itEnd--;
		ghidra::PcodeOp* curOp = *itEnd;
		ghidra::Varnode* vOut = curOp->getOut();
		if (!vOut) {
			continue;
		}
		if (vOut->getSpace()->getName() != "stack") {
			continue;
		}
		int stackOffset = vOut->getAddr().getOffset();
		if (stackOffset < endStackOffset || stackOffset >= endStackOffset + 0x2C) {
			continue;
		}
		int idx = (stackOffset - endStackOffset) / 4;
		if (visited.count(idx)) {
			continue;
		}
		visited.insert(idx);
		if (stackOffset % 4) {
			continue;
		}
		z3::context ctx;
		z3::expr formula(ctx);
		try {
			formula = EvaluateVarnode(ctx, curOp, curOp->getIn(1));
		}
		catch (Exception& ex) {
			continue;
		}
		z3::params params(ctx);
		params.set("bv_not_simpl", true);
		formula = formula.simplify(params);
		std::string formulaExpr = formula.to_string();
		ghidra::VarnodeData tmpData;
		if (formula.is_numeral()) {
			tmpData.space = fd->getArch()->getConstantSpace();
			tmpData.offset = formula.as_uint64();
			tmpData.size = 0x4;
			out_ctx.contextMap[idx] = tmpData;
		}
		else if (formula.is_const()) {
			tmpData = fd->getArch()->translate->getRegister(formulaExpr);
			std::string regName = fd->getArch()->translate->getRegisterName(tmpData.space, tmpData.offset, tmpData.size);
			basicReg.insert(regName);
			out_ctx.contextMap[idx] = tmpData;
		}
	}
	//检查基础寄存器
	if (basicReg.size() < 7) {
		return false;
	}
	return true;
}

z3::expr VmpBranchAnalyzer::EvaluateLoadVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
		if (curOp->code() != ghidra::CPUI_STORE) {
			continue;
		}
		ghidra::Varnode* vStoreNode = curOp->getIn(1);
		if (vStoreNode->getSpace() != vn->getSpace()) {
			continue;
		}
		if (vStoreNode->getOffset() != vn->getOffset()) {
			continue;
		}
		if (vStoreNode->getSize() != vn->getSize()) {
			//To to do...
		}
		return EvaluateVarnode(ctx, curOp, curOp->getIn(2));
	}
	if (bLoaded) {
		throw Exception("too much esp load");
	}
	bLoaded = true;
	return EvaluateVarnode(ctx, op, vn);
}

z3::expr VmpBranchAnalyzer::EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
		if (vOut->getSize() != vn->getSize()) {
			//To do...
		}
		return EvaluatePcodeOp(ctx, curOp);
	}
	return ctx.bv_val(0x0, 32);
}

z3::expr VmpBranchAnalyzer::EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
	throw Exception("bad varnode");
}

z3::expr VmpBranchAnalyzer::EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp)
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
	case ghidra::CPUI_INT_AND:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) & EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_OR:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) | EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_NEGATE:
		return ~EvaluateVarnode(ctx, defOp, defOp->getIn(0));
	case ghidra::CPUI_INT_LEFT:
	case ghidra::CPUI_INT_RIGHT:
		//一般是处理flag了
		return ctx.bv_const("flag", 32);
	case ghidra::CPUI_LOAD:
		return EvaluateLoadVarnode(ctx, defOp, defOp->getIn(1));
	default:
		break;
	}
	throw Exception("bad defcode");
}

std::vector<size_t> VmpBranchAnalyzer::guessConditionalBranch(z3::expr& formula)
{
	std::vector<size_t> retList;
	std::vector<z3::expr> exprList;
	std::set<size_t> filterSet;
	exprList.push_back(formula);
	while (!exprList.empty()) {
		z3::expr tmpExpr = exprList.back();
		exprList.pop_back();
		if (tmpExpr.is_app() && tmpExpr.decl().decl_kind() == Z3_OP_BNOT) {
			if (tmpExpr.arg(0).is_numeral()) {
				size_t endAddr = tmpExpr.arg(0).as_uint64();
				if (!filterSet.count(endAddr)) {
					filterSet.insert(endAddr);
					retList.push_back(endAddr);
				}
				continue;
			}
		}
		for (unsigned i = 0; i < tmpExpr.num_args(); ++i) {
			exprList.push_back(tmpExpr.arg(i));
		}

	}
	return retList;
}

bool VmpExitCallAnalyzer::getEndStackOffset(int& outOffset)
{
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	if (!retOp) {
		return false;
	}
	ghidra::PcodeOp* defOp = nullptr;
	for (unsigned int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vn = retOp->getIn(n);
		std::string retRegName = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
		if (retRegName != "ESP") {
			continue;
		}
		defOp = vn->getDef();
	}
	if (!defOp) {
		return false;
	}
	z3::context ctx;
	z3::expr formula(ctx);
	try {
		formula = EvaluatePcodeOp(ctx, defOp);
	}
	catch (Exception& ex) {
		return false;
	}
	formula = formula.simplify();
	std::string ss2 = formula.to_string();
	if (formula.is_app() && formula.decl().decl_kind() == Z3_OP_BADD) {
		z3::expr arg1 = formula.arg(0);
		z3::expr arg2 = formula.arg(1);
		if (arg1.is_numeral() && arg2.decl().name().str() == "ESP") {
			outOffset = arg1.as_int64();
			return true;
		}
	}
	else if (formula.is_const() && formula.decl().name().str() == "ESP") {
		outOffset = 0x0;
		return true;
	}
	return false;
}

z3::expr VmpExitCallAnalyzer::EvaluatePcodeOp(z3::context& ctx, ghidra::PcodeOp* defOp)
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
	case ghidra::CPUI_INT_AND:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) & EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_OR:
		return EvaluateVarnode(ctx, defOp, defOp->getIn(0)) | EvaluateVarnode(ctx, defOp, defOp->getIn(1));
	case ghidra::CPUI_INT_NEGATE:
		return ~EvaluateVarnode(ctx, defOp, defOp->getIn(0));
	case ghidra::CPUI_INT_LEFT:
	case ghidra::CPUI_INT_RIGHT:
		//一般是处理flag了
		return ctx.bv_const("flag", 32);
	default:
		break;
	}
	throw Exception("bad defcode");
}

z3::expr VmpExitCallAnalyzer::EvaluateVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
	throw Exception("bad varnode");
}

z3::expr VmpExitCallAnalyzer::EvalutaeStackVarnode(z3::context& ctx, ghidra::PcodeOp* op, ghidra::Varnode* vn)
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
		if (vOut->getSize() != vn->getSize()) {
			//To do...
		}
		return EvaluatePcodeOp(ctx, curOp);
	}
	return ctx.bv_val(0x0, 32);
}


size_t VmpExitCallAnalyzer::GuessExitCallAddr(ghidra::Funcdata* func)
{
	fd = func;
	bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return 0x0;
	}
	int endStackOffset = 0x0;
	if (!getEndStackOffset(endStackOffset)) {
		return 0x0;
	}
	//倒序遍历基本块
	ghidra::Varnode* vExitNode = nullptr;
	ghidra::PcodeOp* curOp = nullptr;
	auto itEnd = bb->endOp();
	while (itEnd != bb->beginOp()) {
		--itEnd;
		curOp = *itEnd;
		ghidra::Varnode* vOut = curOp->getOut();
		if (!vOut) {
			continue;
		}
		if (vOut->getSpace()->getName() != "stack") {
			continue;
		}
		int stackOffset = vOut->getAddr().getOffset();
		if (stackOffset > endStackOffset && stackOffset < endStackOffset + 0x4) {
			return 0x0;
		}
		if (stackOffset != endStackOffset) {
			continue;
		}
		if (vOut->getSize() != 0x4) {
			return 0x0;
		}
		vExitNode = vOut;
		break;
	}
	if (!vExitNode) {
		return 0x0;
	}
	z3::context ctx;
	z3::expr formula(ctx);
	try {
		formula = EvaluateVarnode(ctx, curOp, vExitNode);
	}
	catch (Exception& ex) {
		return 0x0;
	}
	std::string formulaExpr = formula.to_string();
	formula = formula.simplify();
	if (formula.is_numeral()) {
		size_t endAddr = formula.as_uint64();
		return endAddr;
	}
	return 0x0;
}

std::vector<size_t> VmpBranchAnalyzer::GuessVmpBranch()
{
	std::vector<size_t> retList;
	bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return retList;
	}
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	if (!retOp) {
		return retList;
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
		return retList;
	}
	z3::context ctx;
	z3::expr formula(ctx);
	try {
		formula = EvaluateVarnode(ctx, retOp, vEIP);
	}
	catch (Exception& ex) {
		return retList;
	}
	std::string formulaExpr = formula.to_string();
	if (formula.is_numeral()) {
		size_t endAddr = formula.as_uint64();
		retList.push_back(endAddr);
		return retList;
	}
	auto guessList = guessConditionalBranch(formula);
	if (guessList.size() == 2) {
		return guessList;
	}
	formula = formula.simplify();
	if (formula.is_numeral()) {
		size_t endAddr = formula.as_uint64();
		retList.push_back(endAddr);
		return retList;
	}
	return retList;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif