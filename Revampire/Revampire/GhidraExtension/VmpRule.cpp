#include "VmpRule.h"
#include "../Ghidra/funcdata.hh"
#include "../Helper/IDAWrapper.h"
#include "../Common/Utils/Public.h"

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
