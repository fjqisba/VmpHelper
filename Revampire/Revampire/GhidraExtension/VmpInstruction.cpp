#include "VmpInstruction.h"
#include <functional>
#include <lines.hpp>

void colorAddr(std::ostream& ss, size_t addr, const char* tag)
{
	ss << SCOLOR_ON << tag << std::hex << addr << SCOLOR_OFF << tag;
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

}

void VmpInstruction::printAddress(std::ostream& ss)
{
	colorAddr(ss, addr.vmdata, SCOLOR_DNUM);
	ss << " ";
	colorAddr(ss, addr.raw, SCOLOR_DREF);
}

void VmpOpNand::PrintRaw(std::ostream& ss)
{
	//colorString(ss, DecToHex(vmAddr), SCOLOR_DNUM);
	//ss << " ";
	//colorString(ss, DecToHex(rawAddr), SCOLOR_DREF);
	//ss << "\t";
	//colorString(ss, SCOLOR_INSN, [this, &ss]() {
	//	ss << "vNand" << this->opSize;
	//	});
	//ss << "\n";
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

void VmpOpJmp::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, "vJmp", SCOLOR_INSN);
	ss << "\n";
}

void VmpOpPopReg::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vStore" << this->opSize << " " << std::hex << vmRegOffset;
	});
	ss << "\n";
}

void VmpOpPushReg::PrintRaw(std::ostream& ss)
{
	printAddress(ss);
	ss << "\t";
	colorString(ss, SCOLOR_INSN, [this, &ss]() {
		ss << "vLoad" << this->opSize << " " << std::hex << vmRegOffset;
	});
	ss << "\n";
}