#include "VmpUnicorn.h"
#include <sstream>
#include "../Manager/DisasmManager.h"
#include "../Manager/SectionManager.h"
#include "../Common/Public.h"

VmpUnicorn::VmpUnicorn()
{

}

VmpUnicorn::~VmpUnicorn()
{
    clear();
}

uc_err read_reg_context(uc_engine* uc, reg_context& outContext)
{
    const int reg_arg[10] = { UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,UC_X86_REG_ESP,UC_X86_REG_EBP,
               UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EIP,UC_X86_REG_EFLAGS };
    void* ptrs[10];
    unsigned int* pRegAddr = &outContext.EAX;
    for (int n = 0; n < 10; n++) {
        ptrs[n] = pRegAddr++;
    }
    return uc_reg_read_batch(uc, (int*)reg_arg, ptrs, 10);
}

uc_err write_reg_context(uc_engine* uc, const reg_context& regContext)
{
    const int reg_arg[10] = { UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,UC_X86_REG_ESP,UC_X86_REG_EBP,
               UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EIP,UC_X86_REG_EFLAGS };
    void* ptrs[10];
    const unsigned int* pRegAddr = &regContext.EAX;
    for (int n = 0; n < 10; n++) {
        ptrs[n] = (void*)pRegAddr++;
    }
    return uc_reg_write_batch(uc, (int*)reg_arg, ptrs, 10);
}

void VmpUnicorn::cb_hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    VmpUnicorn* unicornMgr = (VmpUnicorn*)user_data;
    switch (type) {
    case UC_MEM_READ_UNMAPPED:
    case UC_MEM_WRITE_UNMAPPED:
        unicornMgr->bContinue = true;
        break;
    case UC_MEM_FETCH_UNMAPPED:
        unicornMgr->bContinue = false;
        break;
    default:
        int a = 0;
        break;
    }
    uc_emu_stop(uc);
}

void VmpUnicorn::cb_hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    VmpUnicorn* unicornMgr = (VmpUnicorn*)user_data;
    read_reg_context(uc, unicornMgr->tmpContext);
    unicornMgr->traceList.push_back(unicornMgr->tmpContext);
}

bool VmpUnicorn::fillRegister(const VmpUnicornContext& ctx)
{
    //除了ESP以外,其余的寄存器只能为0
    write_reg_context(uc, ctx.context);
    return true;
}

bool VmpUnicorn::fillMemoryMap()
{
    SectionManager& secMgr = SectionManager::Main();
    SegmentInfomation& firstSeg = secMgr.segList[0];
    SegmentInfomation& lastSeg = secMgr.segList[secMgr.segList.size() - 1];
    unsigned int programSize = AlignByMemory(lastSeg.segStart + lastSeg.segSize - firstSeg.segStart, 0x1000);
    //写到模拟器中
    uc_err err = uc_mem_map(uc, firstSeg.segStart, programSize, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        return false;
    }
    for (unsigned int n = 0; n < secMgr.segList.size(); n++) {
        err = uc_mem_write(uc, secMgr.segList[n].segStart, secMgr.segList[n].segData.data(), secMgr.segList[n].segSize);
        if (err != UC_ERR_OK) {
            return false;
        }
    }
    return true;
}

size_t VmpUnicorn::getNextInsAddr(size_t addr)
{
    auto tmpIns = DisasmManager::Main().DecodeInstruction(addr);
    if (tmpIns == nullptr) {
        return 0x0;
    }
    if (tmpIns->raw->id == X86_INS_JMP) {
        if (tmpIns->raw->detail->x86.operands[0].type == X86_OP_IMM) {
            return tmpIns->raw->detail->x86.operands[0].imm;
        }
    }
    return addr + tmpIns->raw->size;
}

bool VmpUnicorn::fixStack()
{
    //计算要恢复的数据
    auto itBegin = traceList.rbegin();
    auto itEnd = traceList.rend();
    int popCount = 0x0;
    while (itBegin != itEnd) {
        reg_context& endContext = *itBegin++;
        if (endContext.ESP >= stackCodeBase && endContext.ESP < stackCodeBase + stackBuffer.size()) {
            break;
        }
        popCount++;
    }
    if (popCount >= 1) {
        popCount = popCount - 1;
        traceList.resize(traceList.size() - popCount);
        traceList[traceList.size() - 1].ESP = traceList[traceList.size() - 2].ESP;
        write_reg_context(uc, traceList[traceList.size() - 1]);
        return true;
    }
    return false;
}

bool VmpUnicorn::fillStack(const VmpUnicornContext& ctx)
{
    stackCodeBase = ctx.stackCodeBase;
    unsigned int stackSize = ctx.stackBuffer.size();
    uc_mem_unmap(uc, stackCodeBase, stackSize);
    stackBuffer = ctx.stackBuffer;
    auto err = uc_mem_map_ptr(uc, stackCodeBase, stackSize, UC_PROT_ALL, stackBuffer.data());
    if (err != UC_ERR_OK) {
        return false;
    }
    return true;
}

void VmpUnicorn::DumpTrace(std::ostream& ss)
{
    ss << std::hex;
    for (unsigned int n = 0; n < traceList.size(); ++n) {
        ss << "EIP=" << traceList[n].EIP << "\n";
    }
}

std::unique_ptr<VmpUnicornContext> VmpUnicorn::CopyCurrentUnicornContext()
{
    auto retContext = std::make_unique<VmpUnicornContext>();
    retContext->context = this->tmpContext;
    retContext->stackCodeBase = this->stackCodeBase;
    retContext->stackBuffer = this->stackBuffer;
    return retContext;
}

bool VmpUnicorn::ContinueVmpTrace(const VmpUnicornContext& ctx, size_t count)
{
    size_t startAddr = ctx.context.EIP;
    while (true) {
        uc_err err = uc_emu_start(uc, startAddr, 0xFFFFFFFF, 0, count);
        if (bContinue) {
            size_t endAddr = traceList[traceList.size() - 1].EIP;
            std::unique_ptr<RawInstruction> tmpIns = DisasmManager::Main().DecodeInstruction(endAddr);
            if (!tmpIns) {
                return false;
            }
            startAddr = endAddr + tmpIns->raw->size;
            bContinue = false;
            continue;
        }
        break;
    }
    return true;
}

std::vector<reg_context> VmpUnicorn::StartVmpTrace(const VmpUnicornContext& ctx, size_t count)
{
    traceList.clear();
    reset(ctx);
    size_t startAddr = ctx.context.EIP;
    while (traceList.size() < count) {
        uc_err err = uc_emu_start(uc, startAddr, 0xFFFFFFFF, 0, count - traceList.size());
        if (bContinue) {
            fixStack();
            startAddr = getNextInsAddr(traceList[traceList.size() - 1].EIP);
            bContinue = false;
            continue;
        }
        break;
    }
    return traceList;
}

bool VmpUnicorn::reset(const VmpUnicornContext& ctx)
{
    clear();
    init();
    if (!fillMemoryMap()) {
        return false;
    }
    if (!fillStack(ctx)) {
        return false;
    }
    if (!fillRegister(ctx)) {
        return false;
    }
    return true;
}

void VmpUnicorn::clear()
{
    if (hook_mem) {
        uc_hook_del(uc, hook_mem);
        hook_mem = 0x0;
    }
    if (hook_code) {
        uc_hook_del(uc, hook_code);
        hook_code = 0x0;
    }
    if (uc) {
        uc_close(uc);
        uc = nullptr;
    }
}

bool VmpUnicorn::init()
{
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        return false;
    }
    uc_hook_add(uc, &hook_code, UC_HOOK_CODE, cb_hook_code, this, 0x0, 0xFFFFFFFF);
    unsigned int hookType = 0x0;
    hookType |= UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED;
    hookType |= UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT;
    uc_hook_add(uc, &hook_mem, hookType, cb_hook_mem, this, 0x0, 0xFFFFFFFF);
    return true;
}