#include "UnicornHelper.h"
#include <capstone/x86.h>

std::uint32_t reg_context::ReadMemReg(cs_x86_op& op)
{
    size_t retVal = 0x0;
    retVal = ReadReg(op.mem.base) + ReadReg(op.mem.index) * op.mem.scale;
    retVal = retVal + intptr_t(op.mem.disp);
    return retVal;
}

std::uint32_t reg_context::ReadReg(x86_reg reg)
{
    switch (reg) {
    case X86_REG_AL:
        return EAX & 0xFF;
    case X86_REG_BL:
        return EBX & 0xFF;
    case X86_REG_CL:
        return ECX & 0xFF;
    case X86_REG_DL:
        return EDX & 0xFF;
    case X86_REG_AH:
        return EAX & 0xFF00;
    case X86_REG_BH:
        return EBX & 0xFF00;
    case X86_REG_CH:
        return ECX & 0xFF00;
    case X86_REG_DH:
        return EDX & 0xFF00;
    case X86_REG_AX:
        return EAX & 0xFFFF;
    case X86_REG_BX:
        return EBX & 0xFFFF;
    case X86_REG_CX:
        return ECX & 0xFFFF;
    case X86_REG_DX:
        return EDX & 0xFFFF;
    case X86_REG_SP:
        return ESP & 0xFFFF;
    case X86_REG_BP:
        return EBP & 0xFFFF;
    case X86_REG_SI:
        return ESI & 0xFFFF;
    case X86_REG_DI:
        return EDI & 0xFFFF;
    case X86_REG_EAX:
        return EAX;
    case X86_REG_ECX:
        return ECX;
    case X86_REG_EDX:
        return EDX;
    case X86_REG_EBX:
        return EBX;
    case X86_REG_ESP:
        return ESP;
    case X86_REG_EBP:
        return EBP;
    case X86_REG_ESI:
        return ESI;
    case X86_REG_EDI:
        return EDI;
    case X86_REG_EIP:
        return EIP;
    case X86_REG_EFLAGS:
        return EFLAGS;
    }
    return 0x0;
}

std::uint32_t reg_context::ReadReg(const std::string& regName)
{
    if (regName == "AL") {
        return EAX & 0xFF;
    }
    else if (regName == "BL") {
        return EBX & 0xFF;
    }
    else if (regName == "CL") {
        return ECX & 0xFF;
    }
    else if (regName == "DL") {
        return EDX & 0xFF;
    }
    else if (regName == "AH") {
        return EAX & 0xFF00;
    }
    else if (regName == "BH") {
        return EBX & 0xFF00;
    }
    else if (regName == "CH") {
        return ECX & 0xFF00;
    }
    else if (regName == "DH") {
        return EDX & 0xFF00;
    }
    else if (regName == "AX") {
        return EAX & 0xFFFF;
    }
    else if (regName == "BX") {
        return EBX & 0xFFFF;
    }
    else if (regName == "CX") {
        return ECX & 0xFFFF;
    }
    else if (regName == "DX") {
        return EDX & 0xFFFF;
    }
    else if (regName == "SP") {
        return ESP & 0xFFFF;
    }
    else if (regName == "BP") {
        return EBP & 0xFFFF;
    }
    else if (regName == "SI") {
        return ESI & 0xFFFF;
    }
    else if (regName == "DI") {
        return EDI & 0xFFFF;
    }
    else if (regName == "EAX") {
        return EAX;
    }
    else if (regName == "EBX") {
        return EBX;
    }
    else if (regName == "ECX") {
        return ECX;
    }
    else if (regName == "EDX") {
        return EDX;
    }
    else if (regName == "ESP") {
        return ESP;
    }
    else if (regName == "EBP") {
        return EBP;
    }
    else if (regName == "ESI") {
        return ESI;
    }
    else if (regName == "EDI") {
        return EDI;
    }
    else if (regName == "eflags") {
        return EFLAGS;
    }
    return 0x0;
}

std::unique_ptr<VmpUnicornContext> VmpUnicornContext::DefaultContext()
{
    auto retContext = std::make_unique<VmpUnicornContext>();
    retContext->stackCodeBase = 0x10000;
    retContext->stackBuffer.resize(0x10000, 0x0);

    retContext->context.EAX = 0x0;
    retContext->context.EBX = 0x0;
    retContext->context.ECX = 0x0;
    retContext->context.EDX = 0x0;
    retContext->context.ESP = DefaultEsp();
    retContext->context.EBP = 0x0;
    retContext->context.ESI = 0x0;
    retContext->context.EDI = 0x0;
    retContext->context.EFLAGS = 0x0;
    return retContext;
}

size_t VmpUnicornContext::DefaultEsp()
{
    const unsigned int magicEsp = 0x1A000;
    return magicEsp;
}