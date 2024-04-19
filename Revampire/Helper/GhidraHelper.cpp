#include "GhidraHelper.h"
#include "../Ghidra/funcdata.hh"
#include "../GhidraExtension/VmpArch.h"

using namespace GhidraHelper;

void VmpBranchExtractor::checkBranchPattern(ghidra::PcodeOp* curOp)
{
	if (curOp == nullptr) {
		return;
	}
	auto code = curOp->code();
	switch (code) {
	case ghidra::CPUI_INT_ADD:
	case ghidra::CPUI_INT_SUB:
		anaList.push_back(curOp->getIn(0)->getDef());
		anaList.push_back(curOp->getIn(1)->getDef());
		return;
	case ghidra::CPUI_COPY:
		anaList.push_back(curOp->getIn(0)->getDef());
		return;
	}
	if (code == ghidra::CPUI_INT_NEGATE) {
		ghidra::PcodeOp* defOp = curOp->getIn(0)->getDef();
		if (defOp && defOp->code() == ghidra::CPUI_INT_OR && defOp->getIn(1)->isConstant()) {
			unsigned int nextBranchData = defOp->getIn(1)->getOffset();
			nextBranchData = ~nextBranchData;
			branchList.push_back(nextBranchData);
			return;
		}
		anaList.push_back(defOp);
	}
	return;
}


std::vector<size_t> VmpBranchExtractor::ExtractVmAllBranch(ghidra::Funcdata* fd)
{
	std::vector<size_t> nextBrachList;
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	if (!retOp) {
		return nextBrachList;
	}
	for (unsigned int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vn = retOp->getIn(n);
        std::string retRegName = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
		if (retRegName != "EIP") {
			continue;
		}
		ghidra::PcodeOp* defOp = vn->getDef();
		if (!defOp) {
			continue;
		}
		if (defOp->code() == ghidra::CPUI_COPY && defOp->getIn(0)->isConstant()) {
			nextBrachList.push_back(defOp->getIn(0)->getAddr().getOffset());
			return nextBrachList;
		}
		anaList.push_back(defOp);
	}
	while (!anaList.empty()) {
		ghidra::PcodeOp* anaOp = anaList.back();
		anaList.pop_back();
		checkBranchPattern(anaOp);
		if (branchList.size() == 2) {
			nextBrachList = branchList;
			return nextBrachList;
		}
	}
    return nextBrachList;
}

void PcodeOpTracer::traceOpCode(ghidra::PcodeOp* op, bool bAccessMem, std::vector<TraceResult>& outResult)
{
    if (!op) {
        return;
    }
    auto code = op->code();
    int inputNum = op->numInput();
    if (code == ghidra::CPUI_CALLOTHER) {
        ghidra::UserPcodeOp* userOp = fd->getArch()->userops.getOp(op->getIn(0)->getOffset());
        if (userOp) {
            TraceResult tmpResult;
            tmpResult.name = userOp->getOperatorName(op);
            tmpResult.addr = op->getAddr().getOffset();
            if (!filterResult.count(tmpResult)) {
                filterResult.insert(tmpResult);
                outResult.push_back(tmpResult);
            }
        }
        return;
    }
    if (code == ghidra::CPUI_LOAD) {
        bAccessMem = true;
    }
    for (int n = 0; n < inputNum; ++n) {
        traceNode(op->getAddr().getOffset(), op->getIn(n), bAccessMem, outResult);
    }
}

void PcodeOpTracer::traceNode(size_t opAddr, ghidra::Varnode* vn, bool bAccessMem, std::vector<TraceResult>& outResult)
{
    if (vn->isInput()) {
        TraceResult tmpResult;
        if (vn->getSpace()->getName() == "stack") {
            tmpResult.name = "stack";
        }
        else if (vn->getSpace()->getName() == "ram") {
            tmpResult.name = "ram";
        }
        else {
            tmpResult.name = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
        }
        tmpResult.addr = opAddr;
        tmpResult.bAccessMem = bAccessMem;
        tmpResult.offset = vn->getOffset();
        if (!filterResult.count(tmpResult)) {
            filterResult.insert(tmpResult);
            outResult.push_back(tmpResult);
        }
        return;
    }
    traceOpCode(vn->getDef(), bAccessMem, outResult);
}

std::vector<TraceResult> PcodeOpTracer::TraceInput(size_t startAddr, ghidra::Varnode* vn)
{
    std::vector<TraceResult> retResult;
    traceNode(startAddr, vn, false, retResult);
    return retResult;
}

std::string GhidraHelper::GetVarnodeRegName(ghidra::Varnode* vn)
{
	if (vn->getSpace()->getName() != "register") {
		return "";
	}
	return gArch->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
}