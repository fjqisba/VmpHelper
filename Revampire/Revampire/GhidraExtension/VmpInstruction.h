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
	VM_JMP_CONST,
	VM_READ_MEM,
	VM_WRITE_MEM,
	VM_PUSH_VSP,
	VM_WRITE_VSP,
	VM_IMUL,

	USER_CONNECT,
};

enum VmJmpType
{
	V_UNKNOWN = 0x0,
	V_JMP = 0x1,
	V_JCC = 0x2,
	V_CASE = 0x3,
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

class VmpOpInit :public VmpInstruction
{
public:
	VmpOpInit() { opType = VM_INIT; };
	~VmpOpInit() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
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
public:
	//退出的寄存器
	std::vector<ghidra::VarnodeData> exitContext;
	size_t exitAddress = 0x0;
};

class VmpOpPopReg :public VmpInstruction
{
public:
	VmpOpPopReg() { opType = VM_POP_REG; };
	~VmpOpPopReg() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
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
	int BuildInstruction(ghidra::Funcdata& data);
private:
	int BuildNor1(ghidra::Funcdata& data);
	int BuildNor2(ghidra::Funcdata& data);
	int BuildNor4(ghidra::Funcdata& data);
};

class VmpOpShr : public VmpInstruction
{
public:
	VmpOpShr() { opType = VM_SHR; };
	~VmpOpShr() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
private:
	int BuildShr1(ghidra::Funcdata& data);
	int BuildShr2(ghidra::Funcdata& data);
	int BuildShr4(ghidra::Funcdata& data);
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
public:
	//VmJmpType jmpType;
	std::vector<size_t> branchList;
	//是否建立Jmp
	bool isBuildJmp = false;
};

class VmpOpReadMem :public VmpInstruction
{
public:
	VmpOpReadMem() { opType = VM_READ_MEM; };
	~VmpOpReadMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
};

class VmpOpWriteMem :public VmpInstruction
{
public:
	VmpOpWriteMem() { opType = VM_WRITE_MEM; };
	~VmpOpWriteMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
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