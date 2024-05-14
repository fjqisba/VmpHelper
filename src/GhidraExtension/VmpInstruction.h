#pragma once
#include <cereal/cereal.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/archives/binary.hpp>
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
	VM_DIV,
	VM_NOR,
	VM_NAND,
	VM_SHR,
	VM_SHRD,
	VM_SHL,
	VM_SHLD,
	VM_JMP,
	VM_JMP_CONST,
	VM_READ_MEM,
	VM_WRITE_MEM,
	VM_PUSH_VSP,
	VM_WRITE_VSP,
	VM_MUL,
	VM_IMUL,
	VM_CPUID,
	VM_RDTSC,
	VM_POPFD,
	VM_EXIT_CALL,
	VM_COPYSTACK,
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
class VmpNode;
class VmpFlowBuildContext;

class VmpInstruction :public vm_inst
{
public:
	VmpInstruction() {};
	virtual ~VmpInstruction() {};
	bool IsRawInstruction() override { return false; };
	virtual int BuildInstruction(ghidra::Funcdata& data);
	virtual void BuildX86Asm(triton::Context* ctx);
	virtual std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input);
	virtual void PrintRaw(std::ostream& ss);

	void printAddress(std::ostream& ss);
	VmAddress GetAddress() override { return addr; };
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(addr, opType, opSize);
	}
	static size_t GetMemAccessSize(size_t addr);
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

class VmpOpCopyStack :public VmpInstruction
{
public:
	VmpOpCopyStack() { opType = VM_COPYSTACK; };
	~VmpOpCopyStack() {};
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpRdtsc :public VmpInstruction
{
public:
	VmpOpRdtsc() { opType = VM_RDTSC; };
	~VmpOpRdtsc() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpPopfd :public VmpInstruction
{
public:
	VmpOpPopfd() { opType = VM_POPFD; };
	~VmpOpPopfd() {};
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this), storeAddr, reg_code, reg_stack);
	}
public:
	size_t storeAddr = 0x0;
	std::string reg_code;
	std::string reg_stack;
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this), loadAddr);
	}
public:
	size_t loadAddr = 0x0;
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this), loadAddr, storeAddr);
	}
public:
	size_t loadAddr;
	size_t storeAddr;
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpDiv : public VmpInstruction
{
public:
	VmpOpDiv() { opType = VM_DIV; };
	~VmpOpDiv() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpNand :public VmpInstruction
{
public:
	VmpOpNand() { opType = VM_NAND; };
	~VmpOpNand() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpNor :public VmpInstruction
{
public:
	VmpOpNor() { opType = VM_NOR; };
	~VmpOpNor() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data);
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpShr : public VmpInstruction
{
public:
	VmpOpShr() { opType = VM_SHR; };
	~VmpOpShr() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpShrd : public VmpInstruction
{
public:
	VmpOpShrd() { opType = VM_SHRD; };
	~VmpOpShrd() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpShl : public VmpInstruction
{
public:
	VmpOpShl() { opType = VM_SHL; };
	~VmpOpShl() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
private:
	int BuildShl1(ghidra::Funcdata& data);
	int BuildShl2(ghidra::Funcdata& data);
	int BuildShl4(ghidra::Funcdata& data);
};

class VmpOpShld : public VmpInstruction
{
public:
	VmpOpShld() { opType = VM_SHLD; };
	~VmpOpShld() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpJmp :public VmpInstruction
{
public:
	VmpOpJmp() { opType = VM_JMP; };
	~VmpOpJmp() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this), seg);
	}
public:
	std::string seg;
};

class VmpOpWriteMem :public VmpInstruction
{
public:
	VmpOpWriteMem() { opType = VM_WRITE_MEM; };
	~VmpOpWriteMem() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx,VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpPushVSP :public VmpInstruction
{
public:
	VmpOpPushVSP() { opType = VM_PUSH_VSP; };
	~VmpOpPushVSP() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpWriteVSP :public VmpInstruction
{
public:
	VmpOpWriteVSP() { opType = VM_WRITE_VSP; };
	~VmpOpWriteVSP() {};
	int BuildInstruction(ghidra::Funcdata& data) override;
	void PrintRaw(std::ostream& ss) override;
	void BuildX86Asm(triton::Context* ctx) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
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
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

class VmpOpMul :public VmpInstruction
{
public:
	VmpOpMul() { opType = VM_IMUL; };
	~VmpOpMul() {};
	void PrintRaw(std::ostream& ss) override;
	int BuildInstruction(ghidra::Funcdata& data) override;
	std::unique_ptr<VmpInstruction> MakeInstruction(VmpFlowBuildContext* ctx, VmpNode& input) override;
	template <class Archive>
	void serialize(Archive& ar)
	{
		ar(cereal::base_class<VmpInstruction>(this));
	}
};

#define REGISTER_VMPINSTRUCTION(TYPE) \
    CEREAL_REGISTER_TYPE(TYPE) \
    CEREAL_REGISTER_POLYMORPHIC_RELATION(VmpInstruction, TYPE)

REGISTER_VMPINSTRUCTION(VmpOpPopReg)
REGISTER_VMPINSTRUCTION(VmpOpPushReg)
REGISTER_VMPINSTRUCTION(VmpOpPushImm)
REGISTER_VMPINSTRUCTION(VmpOpPushVSP)
REGISTER_VMPINSTRUCTION(VmpOpWriteMem)
REGISTER_VMPINSTRUCTION(VmpOpReadMem)
REGISTER_VMPINSTRUCTION(VmpOpAdd)
REGISTER_VMPINSTRUCTION(VmpOpNor)
REGISTER_VMPINSTRUCTION(VmpOpNand)
REGISTER_VMPINSTRUCTION(VmpOpShr)
REGISTER_VMPINSTRUCTION(VmpOpShl)
REGISTER_VMPINSTRUCTION(VmpOpShrd)
REGISTER_VMPINSTRUCTION(VmpOpShld)
REGISTER_VMPINSTRUCTION(VmpOpCpuid)
REGISTER_VMPINSTRUCTION(VmpOpImul)
REGISTER_VMPINSTRUCTION(VmpOpJmpConst)
REGISTER_VMPINSTRUCTION(VmpOpJmp)
REGISTER_VMPINSTRUCTION(VmpOpWriteVSP)
REGISTER_VMPINSTRUCTION(VmpOpCopyStack)
REGISTER_VMPINSTRUCTION(VmpOpRdtsc)
REGISTER_VMPINSTRUCTION(VmpOpDiv)
REGISTER_VMPINSTRUCTION(VmpOpMul)