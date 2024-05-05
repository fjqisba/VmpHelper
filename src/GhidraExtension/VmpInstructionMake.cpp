#pragma once
#include "VmpInstruction.h"
#include "../GhidraExtension/VmpNode.h"
#include "../Manager/exceptions.h"

std::unique_ptr<VmpInstruction> VmpInstruction::MakeInstruction(VmpNode& input)
{
	return nullptr;
}

size_t VmpInstruction::GetMemAccessSize(size_t addr)
{
	auto asmData = DisasmManager::Main().DecodeInstruction(addr);
	cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
	if (op1.type == X86_OP_MEM) {
		return op1.size;
	}
	return 0x0;
}

std::unique_ptr<VmpInstruction> VmpOpPopReg::MakeInstruction(VmpNode& input)
{
	std::unique_ptr<VmpOpPopReg> vPopRegOp = std::make_unique<VmpOpPopReg>();
	vPopRegOp->addr = addr;
	vPopRegOp->reg_code = reg_code;
	vPopRegOp->reg_stack = reg_stack;
	vPopRegOp->opSize = GetMemAccessSize(loadAddr);
	for (unsigned int n = 0; n < input.contextList.size(); ++n) {
		reg_context& tmpContext = input.contextList[n];
		if (tmpContext.EIP == storeAddr) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			if (asmData->raw->id == X86_INS_MOV || asmData->raw->id == X86_INS_MOVZX || asmData->raw->id == X86_INS_MOVSX) {
				cs_x86_op& op0 = asmData->raw->detail->x86.operands[0];
				vPopRegOp->vmRegOffset = tmpContext.ReadMemReg(op0);
				return vPopRegOp;
			}
		}
	}
	return nullptr;
}

std::unique_ptr<VmpInstruction> VmpOpPushReg::MakeInstruction(VmpNode& input)
{
	std::unique_ptr<VmpOpPushReg> vPushRegOp = std::make_unique<VmpOpPushReg>();
	vPushRegOp->addr = addr;

	vPushRegOp->opSize = GetMemAccessSize(loadAddr);
	for (unsigned int n = 0; n < input.contextList.size(); ++n) {
		reg_context& tmpContext = input.contextList[n];
		if (tmpContext.EIP == loadAddr) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
			if (op1.type == X86_OP_MEM) {
				vPushRegOp->vmRegOffset = tmpContext.ReadMemReg(op1);
				return vPushRegOp;
			}
		}
	}
	return nullptr;
}

std::unique_ptr<VmpInstruction> VmpOpPushImm::MakeInstruction(VmpNode& input)
{
	std::unique_ptr<VmpOpPushImm> vPushImm = std::make_unique<VmpOpPushImm>();
	vPushImm->addr = addr;

	vPushImm->opSize = GetMemAccessSize(loadAddr);
	for (unsigned int n = 0; n < input.contextList.size(); ++n) {
		reg_context& tmpContext = input.contextList[n];
		if (tmpContext.EIP == storeAddr) {
			auto tmpIns = DisasmManager::Main().DecodeInstruction(storeAddr);
			cs_x86_op& op0 = tmpIns->raw->detail->x86.operands[0];
			cs_x86_op& op1 = tmpIns->raw->detail->x86.operands[1];
			if (op0.type == X86_OP_MEM && op1.type == X86_OP_REG) {
				vPushImm->immVal = tmpContext.ReadReg(op1.reg);
				return vPushImm;
			}
		}
	}
	return nullptr;
}

std::unique_ptr<VmpInstruction> VmpOpPushVSP::MakeInstruction(VmpNode& input)
{
	std::unique_ptr<VmpOpPushVSP> vPushVSP = std::make_unique<VmpOpPushVSP>();
	vPushVSP->addr = addr;
	return vPushVSP;
}