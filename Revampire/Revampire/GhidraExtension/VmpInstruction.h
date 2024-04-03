#pragma once
#include "../Manager/DisasmManager.h"

class VmpInstruction :public vm_inst
{
public:
	bool IsRawInstruction() override { return false; };
};