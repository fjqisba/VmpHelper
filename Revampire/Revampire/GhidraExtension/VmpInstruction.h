#pragma once
#include "../Manager/DisasmManager.h"
#include "../Ghidra/varnode.hh"
#include "../Common/VmpCommon.h"

enum VmpOpType
{
	VM_UNKNOWN = 0x0,
	VM_INIT,
	VM_EXIT,
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
	VM_READ_MEM,
	VM_WRITE_MEM,
	VM_PUSH_VSP,
	VM_WRITE_VSP,
	VM_IMUL,
};

class VmpInstruction :public vm_inst
{
public:
	VmpInstruction() {};
	virtual ~VmpInstruction() {};
	bool IsRawInstruction() override { return false; };
	virtual int BuildInstruction(ghidra::Funcdata& data);
	void PrintRaw(std::ostream& ss);
	void printAddress(std::ostream& ss);
	VmAddress GetAddress() override { return addr; };
public:
	VmAddress addr;
	VmpOpType opType;
	size_t opSize;
};

class VmpOpUnknown :public VmpInstruction
{
public:
	VmpOpUnknown() { opType = VM_UNKNOWN; };
	~VmpOpUnknown() {};
	void PrintRaw(std::ostream& ss) override;
};

class VmpOpInit :public VmpInstruction
{
public:
	VmpOpInit() { opType = VM_INIT; };
	~VmpOpInit() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
public:
	//Ñ¹ÈëµÄ¶ÑÕ»
	std::vector<ghidra::VarnodeData> storeContext;
};

class VmpOpExit :public VmpInstruction
{
public:
	VmpOpExit() { opType = VM_EXIT; };
	~VmpOpExit() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
public:
	//ÍË³öµÄ¼Ä´æÆ÷
	std::vector<ghidra::VarnodeData> exitContext;
};

//vPopReg2
//mov cx, word ptr ds:[vmstack]
//lea vmstack, ds:[vmstack+0x2]
//mov word ptr ss:[vmReg], cx

//vPopReg4
//mov ecx,dword ptr ds:[vmstack]
//vmstack edi,0x4
//mov dword ptr ss:[vmReg],ecx

class VmpOpPopReg :public VmpInstruction
{
public:
	VmpOpPopReg() { opType = VM_POP_REG; };
	~VmpOpPopReg() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
public:
	//¼Ä´æÆ÷Æ«ÒÆ
	int vmRegOffset;
};

//PushImm1
//movzx ecx,byte ptr ss:[ebp]
//lea esi,dword ptr ds:[esi-0x2]
//mov word ptr ds:[esi],cx

//PushImm2
//movzx edx,word ptr ds:[esi]
//sub edi,0x2
//mov word ptr ds:[edi],dx

//PushImm4
//mov eax,dword ptr ds:[esi]
//lea esi,dword ptr ds:[esi+0x4]
//mov dword ptr ds:[edi],eax

class VmpOpPushImm :public VmpInstruction
{
public:
	VmpOpPushImm() { opType = VM_PUSH_IMM; };
	~VmpOpPushImm() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
private:
	int BuildPushImm1(ghidra::Funcdata& data);
	int BuildPushImm2(ghidra::Funcdata& data);
	int BuildPushImm4(ghidra::Funcdata& data);
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
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
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
	int BuildInstruction(ghidra::Funcdata& data);
	void PrintRaw(std::ostream& ss) override;
private:
	int BuildNand1(ghidra::Funcdata& data);
	int BuildNand2(ghidra::Funcdata& data);
	int BuildNand4(ghidra::Funcdata& data);
};

class VmpOpNor :public VmpInstruction
{
public:
	VmpOpNor() { opType = VM_NOR; };
	~VmpOpNor() {};
	void PrintRaw(std::ostream& ss) override;
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
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
public:
	std::vector<size_t> branchList;
};


class VmpOpReadMem :public VmpInstruction
{
public:
	VmpOpReadMem() { opType = VM_READ_MEM; };
	~VmpOpReadMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
};

class VmpOpWriteMem :public VmpInstruction
{
public:
	VmpOpWriteMem() { opType = VM_WRITE_MEM; };
	~VmpOpWriteMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
public:
};



class VmpOpPushVSP :public VmpInstruction
{
public:
	VmpOpPushVSP() { opType = VM_PUSH_VSP; };
	~VmpOpPushVSP() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
};


class VmpOpWriteVSP :public VmpInstruction
{
public:
	VmpOpWriteVSP() { opType = VM_WRITE_VSP; };
	~VmpOpWriteVSP() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
};

//mov eax, dword ptr ds:[vmstack + 4]
//mov edx, dword ptr ds:[vmstack]
//imul edx
//mov dword ptr ds:[vmstack+0x4], edx
//mov dword ptr ds:[vmstack+0x8], eax
//pushfd
//pop dword ptr ds:[vmstack]

class VmpOpImul :public VmpInstruction
{
public:
	VmpOpImul() { opType = VM_IMUL; };
	~VmpOpImul() {};
	void PrintRaw(std::ostream& ss) override;
};