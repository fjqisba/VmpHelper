#include "AsmBuilder.h"
#include "../Manager/exceptions.h"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

AsmBuilder::AsmBuilder(ks_arch arch, int mode)
{
	ks_err err = ks_open(arch, mode, &ks);
	if (err != KS_ERR_OK) {
		throw KeystoneException("ERROR: failed on ks_open()");
	}
}

X86AsmBuilder::X86AsmBuilder():AsmBuilder(KS_ARCH_X86, KS_MODE_32)
{

}

X86AsmBuilder::~X86AsmBuilder()
{
	
}

AsmBuilder::~AsmBuilder()
{
	if (ks) {
		ks_close(ks);
	}
}

std::unique_ptr<AsmEncodeBuffer> AsmBuilder::EncodeAsm(size_t addr,const std::string& asmStr)
{
	auto ret = std::make_unique<AsmEncodeBuffer>();
	size_t count;
	if (ks_asm(ks, asmStr.c_str(), addr, &ret->encode, &ret->encode_size, &count)) {
		throw AsmBuilderException("EncodeAsm error:" + asmStr);
	}
	return ret;
}

X86AsmBuilder& AsmBuilder::X86()
{
	static X86AsmBuilder gX86Builder;
	return gX86Builder;
}

std::unique_ptr<AsmEncodeBuffer> X86AsmBuilder::pop_reg(const std::string& regName)
{
	auto ret = std::make_unique<AsmEncodeBuffer>();
	size_t count;
	std::string asmStr;
	if (regName == "eflags") {
		asmStr = "popfd";
	}
	else {
		asmStr = "pop " + regName;
	}
	if (ks_asm(ks, asmStr.c_str(), 0, &ret->encode, &ret->encode_size, &count)) {
		throw AsmBuilderException("pop_reg error");
	}
	return ret;
}

std::unique_ptr<AsmEncodeBuffer> X86AsmBuilder::push_reg(const std::string& regName)
{
	auto ret = std::make_unique<AsmEncodeBuffer>();
	size_t count;
	std::string asmStr;
	if (regName == "eflags") {
		asmStr = "PUSHFD";
	}
	else {
		asmStr = "PUSH " + regName;
	}
	if (ks_asm(ks, asmStr.c_str(), 0, &ret->encode, &ret->encode_size, &count)) {
		throw AsmBuilderException("push_reg error");
	}
	return ret;
}

std::unique_ptr<AsmEncodeBuffer> X86AsmBuilder::push_const(size_t val)
{
	auto ret = std::make_unique<AsmEncodeBuffer>();
	size_t count;
	std::string asmName = "PUSH " + std::to_string(val);
	if (ks_asm(ks, asmName.c_str(), 0, &ret->encode, &ret->encode_size, &count)) {
		throw AsmBuilderException("push_const error");
	}
	return ret;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif