#pragma once
#include "../Manager/DisasmManager.h"
#include "../Ghidra/varnode.hh"
#include "../Common/VmpCommon.h"

enum VmpOpType
{
	VM_UNKNOWN = 0x0,
	VM_INIT,
	VM_STORE_CONTEXT,
	VM_NOP,
	VM_LOAD,
	VM_POP_REG,
	VM_PUSH_IMM,
	VM_CHECK_ESP,
	VM_IMUL,
	VM_ADD,
	VM_READ_MEM,
	VM_WRITE_MEM,
	VM_JMP,
	VM_JMP_CONST,
	VM_EXIT,
	VM_CPUID,
	VM_RDTSC,
	VM_NAND,
	VM_NOR,
	VM_DIV,
	VM_SHR,
	VM_SHL,
	VM_PUSH_ESP,
	VM_WRITE_ESP,
	//——————
	VM_LOAD_STACK,
	VM_SPLIT,
	//标记最大值
	VM_OPMAX,
};

class VmpInstruction :public vm_inst
{
public:
	bool IsRawInstruction() override { return false; };
public:
	VmAddress addr;
	VmpOpType opType;
	unsigned char opSize;
};

class VmpOpInit :public VmpInstruction
{
public:
	VmpOpInit() { opType = VM_INIT; };
	~VmpOpInit() {};
public:
	//压入的堆栈
	std::vector<ghidra::VarnodeData> storeContext;
};

class VmpOpPopReg :public VmpInstruction
{
public:
	VmpOpPopReg() { opType = VM_POP_REG; };
	~VmpOpPopReg() {};
public:
	//弹出堆栈的偏移
	int popOffset;
	//寄存器偏移
	int regOffset;
};