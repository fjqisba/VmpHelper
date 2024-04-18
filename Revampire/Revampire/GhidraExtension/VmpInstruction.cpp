#include "VmpInstruction.h"
#include <functional>
#include <lines.hpp>
#include "VmpArch.h"

void colorAddr(std::ostream& ss, size_t addr, const char* tag)
{
	auto archType = gArch->ArchType();
	if (archType == VmpArchitecture::ARCH_X86) {
		ss << SCOLOR_ON << tag <<  "0x" << std::setfill('0') << std::setw(8) << std::hex << addr << SCOLOR_OFF << tag;
	}
	else if(archType == VmpArchitecture::ARCH_X86_64){
		ss << SCOLOR_ON << tag << "0x" << std::setfill('0') << std::setw(16) << std::hex << addr << SCOLOR_OFF << tag;
	}
}

void colorString(std::ostream& ss, const std::string& str, const char* tag)
{
	ss << SCOLOR_ON << tag << str << SCOLOR_OFF << tag;
}

void colorString(std::ostream& ss, const char* tag, const std::function<void()>& outputFunction)
{
	ss << SCOLOR_ON << tag;
	outputFunction();
	ss << SCOLOR_OFF << tag;
}

void VmpInstruction::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vInstruction", SCOLOR_INSN);
	ss << "\n";
}

void VmpInstruction::printAddress(std::ostream& ss)
{
	colorAddr(ss, addr.vmdata, SCOLOR_DNUM);
	ss << " ";
	colorAddr(ss, addr.raw, SCOLOR_DREF);
}

void VmpOpNand::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vNand" << this->opSize;
	});
	ss << "\n";
}

void VmpOpNor::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vNor" << this->opSize;
		});
	ss << "\n";
}

void VmpOpPushImm::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vPushImm" << this->opSize;
	});
	ss << " ";
	colorAddr(ss, immVal, SCOLOR_NUMBER);
	ss << "\n";
}

void VmpOpExit::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vExit", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpInit::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vInit", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpUnknown::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vUnknown", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpJmp::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vJmp", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpJmpConst::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vJmpConst", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpExitCall::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vExitCall" << " 0x" << std::hex << callAddr;
	});
	ss << "\n";
}

void VmpOpWriteVSP::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vWriteVSP", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpPopReg::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vPopReg" << this->opSize << " " << std::hex << vmRegOffset;
	});
	ss << "\n";
}

void VmpOpPushReg::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vPushReg" << this->opSize << " " << std::hex << vmRegOffset;
	});
	ss << "\n";
}

void VmpOpPushVSP::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vPushVSP", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpImul::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vImul", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpShl::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vShl" << this->opSize;
		});
	ss << "\n";
}

void VmpOpShr::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vShr" << this->opSize;
		});
	ss << "\n";
}

void VmpOpAdd::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vAdd" << this->opSize;
	});
	ss << "\n";
}

void VmpOpWriteMem::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vWriteMem" << this->opSize;
		});
	ss << "\n";
}

void VmpOpReadMem::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vReadMem" << this->opSize;
		});
	ss << "\n";
}