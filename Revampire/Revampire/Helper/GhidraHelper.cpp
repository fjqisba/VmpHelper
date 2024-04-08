#include "GhidraHelper.h"
#include "../Ghidra/funcdata.hh"

using namespace GhidraHelper;

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