#pragma once
#include <capstone/capstone.h>
#include <memory>

class vm_inst
{
public:
	vm_inst() {};
	virtual ~vm_inst() {};
public:
	virtual bool IsRawInstruction() = 0;
	virtual void PrintRaw(std::ostream& ss) = 0x0;
};

class RawInstruction :public vm_inst
{
public:
	RawInstruction();
	~RawInstruction();
	bool IsRawInstruction() override { return true; };
	void PrintRaw(std::ostream& ss) override;
public:
	cs_insn* raw;
};

class DisasmManager
{
public:
	static DisasmManager& Main();
	DisasmManager();
	~DisasmManager();
public:
	static bool IsBranchInstruction(cs_insn* ins);
	static bool IsE8Call(cs_insn* ins);
	std::unique_ptr<RawInstruction> DecodeInstruction(size_t addr);
public:
	static csh handle;
};