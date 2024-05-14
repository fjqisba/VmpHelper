#pragma once
#include "VmpInstruction.h"
#include "../GhidraExtension/VmpNode.h"
#include "../GhidraExtension/VmpControlFlow.h"
#include "../Manager/exceptions.h"

size_t VmpInstruction::GetMemAccessSize(size_t addr)
{
	auto asmData = DisasmManager::Main().DecodeInstruction(addr);
	cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
	if (op1.type == X86_OP_MEM) {
		return op1.size;
	}
	return 0x0;
}

std::unique_ptr<VmpInstruction> VmpInstruction::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	return nullptr;
}

std::unique_ptr<VmpInstruction> VmpOpPopReg::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpPopReg> vPopRegOp = std::make_unique<VmpOpPopReg>();
	vPopRegOp->addr = input.readVmAddress(reg_code);
	vPopRegOp->reg_code = reg_code;
	vPopRegOp->reg_stack = reg_stack;
	vPopRegOp->opSize = opSize;
	for (unsigned int n = 0; n < input.contextList.size(); ++n) {
		reg_context& tmpContext = input.contextList[n];
		if (tmpContext.EIP == storeAddr) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			if (asmData->raw->id == X86_INS_MOV || asmData->raw->id == X86_INS_MOVZX || asmData->raw->id == X86_INS_MOVSX) {
				cs_x86_op& op0 = asmData->raw->detail->x86.operands[0];
				int offset = tmpContext.ReadMemReg(op0) - buildCtx->vm_esp_addr;
				vPopRegOp->vmRegOffset = VmpUnicornContext::DefaultEsp() + offset;
				return vPopRegOp;
			}
		}
	}
	return nullptr;
}

std::unique_ptr<VmpInstruction> VmpOpPushReg::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpPushReg> vPushRegOp = std::make_unique<VmpOpPushReg>();
	vPushRegOp->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vPushRegOp->opSize = opSize;
	for (unsigned int n = 0; n < input.contextList.size(); ++n) {
		reg_context& tmpContext = input.contextList[n];
		if (tmpContext.EIP == loadAddr) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
			if (op1.type == X86_OP_MEM) {
				int offset = tmpContext.ReadMemReg(op1) - buildCtx->vm_esp_addr;
				vPushRegOp->vmRegOffset = VmpUnicornContext::DefaultEsp() + offset;
				return vPushRegOp;
			}
		}
	}
	return nullptr;
}

std::unique_ptr<VmpInstruction> VmpOpPushImm::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpPushImm> vPushImm = std::make_unique<VmpOpPushImm>();
	vPushImm->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vPushImm->opSize = opSize;
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

std::unique_ptr<VmpInstruction> VmpOpPushVSP::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpPushVSP> vPushVSP = std::make_unique<VmpOpPushVSP>();
	vPushVSP->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vPushVSP;
}

std::unique_ptr<VmpInstruction> VmpOpWriteMem::MakeInstruction(VmpFlowBuildContext* buildCtx,VmpNode& input)
{
	std::unique_ptr<VmpOpWriteMem> vOpWriteMem = std::make_unique<VmpOpWriteMem>();
	vOpWriteMem->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vOpWriteMem->opSize = opSize;
	return vOpWriteMem;
}

std::unique_ptr<VmpInstruction> VmpOpReadMem::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpReadMem> vOpReadMem = std::make_unique<VmpOpReadMem>();
	vOpReadMem->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vOpReadMem->opSize = opSize;
	vOpReadMem->seg = seg;
	return vOpReadMem;
}

std::unique_ptr<VmpInstruction> VmpOpAdd::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpAdd> vAddOp = std::make_unique<VmpOpAdd>();
	vAddOp->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vAddOp->opSize = opSize;
	return vAddOp;
}

std::unique_ptr<VmpInstruction> VmpOpNor::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpNor> vOpNor = std::make_unique<VmpOpNor>();
	vOpNor->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vOpNor->opSize = opSize;
	return vOpNor;
}

std::unique_ptr<VmpInstruction> VmpOpNand::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpNand> vOpNand = std::make_unique<VmpOpNand>();
	vOpNand->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vOpNand->opSize = opSize;
	return vOpNand;
}

std::unique_ptr<VmpInstruction> VmpOpShr::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpShr> vOpShr = std::make_unique<VmpOpShr>();
	vOpShr->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vOpShr->opSize = opSize;
	return vOpShr;
}

std::unique_ptr<VmpInstruction> VmpOpShl::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpShl> vOpShl = std::make_unique<VmpOpShl>();
	vOpShl->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	vOpShl->opSize = opSize;
	return vOpShl;
}

std::unique_ptr<VmpInstruction> VmpOpShrd::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpShrd> vOpShrd = std::make_unique<VmpOpShrd>();
	vOpShrd->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpShrd;
}

std::unique_ptr<VmpInstruction> VmpOpShld::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpShld> vOpShld = std::make_unique<VmpOpShld>();
	vOpShld->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpShld;
}

std::unique_ptr<VmpInstruction> VmpOpCpuid::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpCpuid> vOpCpuid = std::make_unique<VmpOpCpuid>();
	vOpCpuid->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpCpuid;
}

std::unique_ptr<VmpInstruction> VmpOpImul::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpImul> vOpImul = std::make_unique<VmpOpImul>();
	vOpImul->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpImul;
}

std::unique_ptr<VmpInstruction> VmpOpWriteVSP::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpWriteVSP> vOpWriteVSP = std::make_unique<VmpOpWriteVSP>();
	vOpWriteVSP->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpWriteVSP;
}

std::unique_ptr<VmpInstruction> VmpOpJmpConst::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	if (!buildCtx->vmreg.isSelected) {
		return nullptr;
	}
	std::unique_ptr<VmpOpJmpConst> vOpJmpConst = std::make_unique<VmpOpJmpConst>();
	vOpJmpConst->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpJmpConst;
}

std::unique_ptr<VmpInstruction> VmpOpJmp::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpJmp> vOpJmp = std::make_unique<VmpOpJmp>();
	vOpJmp->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpJmp;
}

std::unique_ptr<VmpInstruction> VmpOpCopyStack::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpCopyStack> vOpCopyStack = std::make_unique<VmpOpCopyStack>();
	vOpCopyStack->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpCopyStack;
}

std::unique_ptr<VmpInstruction> VmpOpRdtsc::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpRdtsc> vOpRdtsc = std::make_unique<VmpOpRdtsc>();
	vOpRdtsc->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpRdtsc;
}

std::unique_ptr<VmpInstruction> VmpOpDiv::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpDiv> vOpDiv = std::make_unique<VmpOpDiv>();
	vOpDiv->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpDiv;
}

std::unique_ptr<VmpInstruction> VmpOpMul::MakeInstruction(VmpFlowBuildContext* buildCtx, VmpNode& input)
{
	std::unique_ptr<VmpOpMul> vOpMul = std::make_unique<VmpOpMul>();
	vOpMul->addr = input.readVmAddress(buildCtx->vmreg.reg_code);
	return vOpMul;
}