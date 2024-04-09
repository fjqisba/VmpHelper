#pragma once
#include "../Manager/DisasmManager.h"
#include "../Ghidra/varnode.hh"
#include "../Common/VmpCommon.h"

enum VmpOpType
{
	VM_UNKNOWN = 0x0,
	VM_INIT,
	VM_POP_REG,
	VM_PUSH_IMM,
	VM_PUSH_REG,
	VM_CHECK_ESP,
	VM_ADD,
	VM_NOR,
	VM_NAND,
	VM_SHR,
	VM_SHL,
	VM_JMP,
};

class VmpInstruction :public vm_inst
{
public:
	VmpInstruction() {};
	virtual ~VmpInstruction() {};
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
	//Ñ¹ÈëµÄ¶ÑÕ»
	std::vector<ghidra::VarnodeData> storeContext;
};

class VmpOpPopReg :public VmpInstruction
{
public:
	VmpOpPopReg() { opType = VM_POP_REG; };
	~VmpOpPopReg() {};
public:
	//¼Ä´æÆ÷Æ«ÒÆ
	int vmRegOffset;
};

class VmpOpPushImm :public VmpInstruction
{
public:
	VmpOpPushImm() { opType = VM_POP_REG; };
	~VmpOpPushImm() {};
public:
	size_t immVal;
};

//vPushReg1
//movzx ecx,byte ptr ds:[vmCode]
//movzx ax,byte ptr ss:[esp+ecx]
//sub vmStack,0x2
//mov word ptr ds:[vmStack],ax

//vPushReg2
//movzx edx, byte ptr ds:[vmCode]
//mov cx, word ptr ss:[esp+edx]
//sub vmStack, 0x2
//mov word ptr ds:[vmStack], cx

//vPushReg4
//movzx ecx, byte ptr ds:[vmCode]
//mov edx, dword ptr ss:[esp+ecx]
//lea vmStack, ss:[vmStack-0x4]
//mov dword ptr ss:[vmStack], edx


class VmpOpPushReg :public VmpInstruction
{
public:
	VmpOpPushReg() { opType = VM_PUSH_REG; };
	~VmpOpPushReg() {};
public:
	//¼Ä´æÆ÷Æ«ÒÆ
	int vmRegOffset;
};

class VmpOpCheckEsp :public VmpInstruction
{
public:
	VmpOpCheckEsp() { opType = VM_CHECK_ESP; };
	~VmpOpCheckEsp() {};
};

class VmpOpAdd : public VmpInstruction
{
public:
	VmpOpAdd() { opType = VM_ADD; };
	~VmpOpAdd() {};
};


class VmpOpNand :public VmpInstruction
{
public:
	VmpOpNand() { opType = VM_NAND; };
	~VmpOpNand() {};
};

class VmpOpNor :public VmpInstruction
{
public:
	VmpOpNor() { opType = VM_NOR; };
	~VmpOpNor() {};
};

class VmpOpShr : public VmpInstruction
{
public:
	VmpOpShr() { opType = VM_SHR; };
	~VmpOpShr() {};
};

class VmpOpShl : public VmpInstruction
{
public:
	VmpOpShl() { opType = VM_SHL; };
	~VmpOpShl() {};
};


//mov edx, dword ptr ss:[vmstack]
//add vmStack, 0x4
//mov vmCode,edx
//mov newStack,vmStack

class VmpOpJmp :public VmpInstruction
{
public:
	VmpOpJmp() { opType = VM_JMP; };
	~VmpOpJmp() {};
public:
	std::vector<size_t> branchList;
};