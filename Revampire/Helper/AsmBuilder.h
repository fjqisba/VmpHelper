#pragma once
#include <keystone/keystone.h>
#include <string>
#include <memory>

class X86AsmBuilder;

class AsmEncodeBuffer
{
public:
	AsmEncodeBuffer()
	{
		encode = nullptr;
		encode_size = 0x0;
	}
	~AsmEncodeBuffer() {
		if (encode) {
			ks_free(encode);
			encode = nullptr;
		}
	}
	unsigned char* encode;
	size_t encode_size;
};

class AsmBuilder
{
public:
	AsmBuilder(ks_arch arch, int mode);
	~AsmBuilder();
	static X86AsmBuilder& X86();
	std::unique_ptr<AsmEncodeBuffer> EncodeAsm(size_t addr, const std::string& asmStr);
public:
	ks_engine* ks = nullptr;
};

class X86AsmBuilder :public AsmBuilder
{
public:
	X86AsmBuilder();
	~X86AsmBuilder();
	std::unique_ptr<AsmEncodeBuffer> push_reg(const std::string& regName);
	std::unique_ptr<AsmEncodeBuffer> pop_reg(const std::string& regName);
	std::unique_ptr<AsmEncodeBuffer> push_const(size_t val);
};