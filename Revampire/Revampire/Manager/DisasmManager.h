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
};

class RawInstruction :public vm_inst
{
public:
	RawInstruction();
	~RawInstruction();
	bool IsRawInstruction() override { return true; };
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
	std::unique_ptr<RawInstruction> DecodeInstruction(size_t addr);
public:
	static csh handle;
};