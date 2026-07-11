#include "VmpRule.h"
#include "../Ghidra/funcdata.hh"
#include "../Helper/IDAWrapper.h"
#include "../Common/Public.h"

using namespace ghidra;

void RuleVmpLoadConst::getOpList(vector<uint4>& oplist) const
{
    oplist.push_back(CPUI_LOAD);
}

int4 RuleVmpLoadConst::applyOp(PcodeOp* op, Funcdata& data)
{
    if (!op->getIn(1)->isConstant()) {
        return 0x0;
    }
    //ÅÐ¶ÏµØÖ·ÊÇ·ñÖ»¶Á
    uint4 property = data.getArch()->symboltab->getProperty(op->getIn(1)->getAddr());
    if (!(property & Varnode::readonly)) {
        return 0x0;
    }
    uintb ramVal = 0x0;
    size_t ramAddr = op->getIn(1)->getOffset();
    size_t opSize = op->getOut()->getSize();
    unsigned char maxBuffer[32] = { 0 };
    IDAWrapper::get_bytes(maxBuffer, opSize, ramAddr);
    if (opSize == 0x1) {
        ramVal = readFromMemory<std::uint8_t>(maxBuffer);
    }
    else if (opSize == 0x2) {
        ramVal = readFromMemory<std::uint16_t>(maxBuffer);
    }
    else if (opSize == 0x4) {
        ramVal = readFromMemory<std::uint32_t>(maxBuffer);
    }
    else if (opSize == 0x8) {
        ramVal = readFromMemory<std::uint64_t>(maxBuffer);
    }
    else {
        return 0x0;
    }
    Varnode* constVn = data.newConstant(opSize, ramVal);
    data.opSetInput(op, constVn, 0);
    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, CPUI_COPY);
    return 0x1;
}

int4 RuleVmpEarlyRemoval::applyOp(PcodeOp* op, Funcdata& data)
{
    Varnode* vn;
    if (op->isCall()) return 0;	// Functions automatically consumed
    if (op->isIndirectSource()) return 0;
    vn = op->getOut();
    if (vn == (Varnode*)0) return 0;
    //  if (vn->isPersist()) return 0;
    if (!vn->hasNoDescend()) return 0;
    if (vn->isAutoLive()) return 0;
    AddrSpace* spc = vn->getSpace();
    if (spc == stackspace) {
        return 0x0;
    }
    if (spc->doesDeadcode()) {
        if (!data.deadRemovalAllowedSeen(spc)) {
            return 0;
        }
    }
    data.opDestroy(op);		// Get rid of unused op
    return 1;
}