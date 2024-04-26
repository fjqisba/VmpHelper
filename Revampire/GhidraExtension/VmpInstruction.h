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
	VM_SHRD,
	VM_SHL,
	VM_JMP,
	VM_JMP_CONST,
	VM_READ_MEM,
	VM_WRITE_MEM,
	VM_PUSH_VSP,
	VM_WRITE_VSP,
	VM_IMUL,
	VM_CPUID,
	VM_EXIT_CALL,
	USER_CONNECT,
};

enum VmJmpType
{
	V_UNKNOWN = 0x0,
	V_JMP = 0x1,
	V_JCC = 0x2,
	V_CASE = 0x3,
};

namespace triton
{
	class Context;
}
class X86AsmBuilder;


class VmpInstruction :public vm_inst
{
public:
	VmpInstruction() {};
	virtual ~VmpInstruction() {};
	bool IsRawInstruction() override { return false; };
	virtual int BuildInstruction(ghidra::Funcdata& data);
	virtual void BuildX86Asm(triton::Context* ctx);
	void PrintRaw(std::ostream& ss);
	void printAddress(std::ostream& ss);
	VmAddress GetAddress() override { return addr; };
public:
	VmAddress addr;
	VmpOpType opType = VM_UNKNOWN;
	size_t opSize = 0x0;
};

//作用只是将汇编块和vm块连接起来

class UserOpConnect :public VmpInstruction
{
public:
	UserOpConnect() { opType = USER_CONNECT; };
	~UserOpConnect() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override {};
public:
	size_t connectAddr = 0x0;
};

class VmpOpUnknown :public VmpInstruction
{
public:
	VmpOpUnknown() { opType = VM_UNKNOWN; };
	~VmpOpUnknown() {};
	void PrintRaw(std::ostream& ss) override;
};

class VmpOpCpuid :public VmpInstruction
{
public:
	VmpOpCpuid() { opType = VM_CPUID; };
	~VmpOpCpuid() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
};

class VmpOpInit :public VmpInstruction
{
public:
	VmpOpInit() { opType = VM_INIT; };
	~VmpOpInit() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
	//压入的堆栈
	std::vector<ghidra::VarnodeData> storeContext;
};

class VmpOpExit :public VmpInstruction
{
public:
	VmpOpExit() { opType = VM_EXIT; };
	~VmpOpExit() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
	//退出的寄存器
	std::vector<ghidra::VarnodeData> exitContext;
	size_t exitAddress = 0x0;
};

class VmpOpExitCall : public VmpInstruction
{
public:
	VmpOpExitCall() { opType = VM_EXIT_CALL; };
	~VmpOpExitCall() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
public:
	size_t callAddr = 0x0;
	size_t exitAddress = 0x0;
};

class VmpOpPopReg :public VmpInstruction
{
public:
	VmpOpPopReg() { opType = VM_POP_REG; };
	~VmpOpPopReg() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
	//寄存器偏移
	int vmRegOffset = 0x0;
};

class VmpOpPushReg :public VmpInstruction
{
public:
	VmpOpPushReg() { opType = VM_PUSH_REG; };
	~VmpOpPushReg() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
	//寄存器偏移
	int vmRegOffset = 0x0;
};

class VmpOpPushImm :public VmpInstruction
{
public:
	VmpOpPushImm() { opType = VM_PUSH_IMM; };
	~VmpOpPushImm() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
	size_t immVal = 0x0;
};

class VmpOpCheckEsp :public VmpInstruction
{
public:
	VmpOpCheckEsp() { opType = VM_CHECK_ESP; };
	~VmpOpCheckEsp() {};
	void PrintRaw(std::ostream& ss) override {};
};

class VmpOpAdd : public VmpInstruction
{
public:
	VmpOpAdd() { opType = VM_ADD; };
	~VmpOpAdd() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	void BuildX86Asm(triton::Context* ctx) override;
};


class VmpOpNand :public VmpInstruction
{
public:
	VmpOpNand() { opType = VM_NAND; };
	~VmpOpNand() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
};

class VmpOpNor :public VmpInstruction
{
public:
	VmpOpNor() { opType = VM_NOR; };
	~VmpOpNor() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data);
	void BuildX86Asm(triton::Context* ctx) override;
};

class VmpOpShr : public VmpInstruction
{
public:
	VmpOpShr() { opType = VM_SHR; };
	~VmpOpShr() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
};

class VmpOpShrd : public VmpInstruction
{
public:
	VmpOpShrd() { opType = VM_SHRD; };
	~VmpOpShrd() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
};

class VmpOpShl : public VmpInstruction
{
public:
	VmpOpShl() { opType = VM_SHL; };
	~VmpOpShl() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
private:
	int BuildShl1(ghidra::Funcdata& data);
	int BuildShl2(ghidra::Funcdata& data);
	int BuildShl4(ghidra::Funcdata& data);
};

class VmpOpJmp :public VmpInstruction
{
public:
	VmpOpJmp() { opType = VM_JMP; };
	~VmpOpJmp() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
	//VmJmpType jmpType;
	std::vector<size_t> branchList;
	//是否建立Jmp
	bool isBuildJmp = false;
};

class VmpOpJmpConst :public VmpInstruction
{
public:
	VmpOpJmpConst() { opType = VM_JMP_CONST; };
	~VmpOpJmpConst() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
public:
	size_t targetAddr = 0x0;
	bool isBuildJmp = false;
};

class VmpOpReadMem :public VmpInstruction
{
public:
	VmpOpReadMem() { opType = VM_READ_MEM; };
	~VmpOpReadMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
};

class VmpOpWriteMem :public VmpInstruction
{
public:
	VmpOpWriteMem() { opType = VM_WRITE_MEM; };
	~VmpOpWriteMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
public:
};

class VmpOpPushVSP :public VmpInstruction
{
public:
	VmpOpPushVSP() { opType = VM_PUSH_VSP; };
	~VmpOpPushVSP() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
};

class VmpOpWriteVSP :public VmpInstruction
{
public:
	VmpOpWriteVSP() { opType = VM_WRITE_VSP; };
	~VmpOpWriteVSP() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
};

//mov eax, dword ptr ds:[VSP + 4]
//mov edx, dword ptr ds:[VSP]
//imul edx
//mov dword ptr ds:[VSP+0x4], edx
//mov dword ptr ds:[VSP+0x8], eax
//pushfd
//pop dword ptr ds:[VSP]

class VmpOpImul :public VmpInstruction
{
public:
	VmpOpImul() { opType = VM_IMUL; };
	~VmpOpImul() {};
	void PrintRaw(std::ostream& ss) override;
};