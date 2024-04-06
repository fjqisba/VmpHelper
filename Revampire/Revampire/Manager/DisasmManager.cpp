#include "DisasmManager.h"
#include "SectionManager.h"
#include "../Helper/IDAWrapper.h"
#include "exceptions.h"

csh DisasmManager::handle;

RawInstruction::RawInstruction()
{
	raw = cs_malloc(DisasmManager::handle);
	if (raw == nullptr) {
		throw DisasmException("cs_malloc error");
	}
}

RawInstruction::~RawInstruction()
{
	cs_free(raw, 1);
}

DisasmManager::DisasmManager()
{
	cs_err err;
	if (IDAWrapper::is64BitProgram()) {
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	}
	else {
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	}
	if (err != CS_ERR_OK) {
		throw DisasmException("cs_open error");
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

DisasmManager& DisasmManager::Main()
{
	static DisasmManager gMainDisasm;
	return gMainDisasm;
}

DisasmManager::~DisasmManager()
{
	cs_close(&handle);
}

std::unique_ptr<RawInstruction> DisasmManager::DecodeInstruction(size_t addr)
{
	std::unique_ptr<RawInstruction> retIns = std::make_unique<RawInstruction>();
	unsigned char tmpInsBuffer[16] = { 0 };
	IDAWrapper::get_bytes(tmpInsBuffer, 16, addr, 0x1);
	size_t maxInsLen = 16;
	unsigned char* pInsBuf = tmpInsBuffer;
	if (cs_disasm_iter(DisasmManager::handle, (const uint8_t**)&pInsBuf, &maxInsLen, (uint64_t*)&addr, retIns->raw)) {
		return retIns;
	}
	return nullptr;
}

bool DisasmManager::IsBranchInstruction(cs_insn* ins)
{
	if (ins->id >= X86_INS_JAE && ins->id <= X86_INS_JS) {
		return true;
	}
	return false;
}

bool DisasmManager::IsE8Call(cs_insn* ins)
{
	if (ins->id != X86_INS_CALL) {
		return false;
	}
	if (ins->detail->x86.opcode[0] != 0xE8) {
		return false;
	}
	return true;
}