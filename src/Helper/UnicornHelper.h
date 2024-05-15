#pragma once
#include <memory>
#include <vector>
#include <string>

enum x86_reg;
struct cs_x86_op;

struct reg_context
{
    std::uint32_t EAX;
    std::uint32_t ECX;
    std::uint32_t EDX;
    std::uint32_t EBX;
    std::uint32_t ESP;
    std::uint32_t EBP;
    std::uint32_t ESI;
    std::uint32_t EDI;
    std::uint32_t EIP;
    std::uint32_t EFLAGS;
public:
    std::uint32_t ReadReg(x86_reg reg);
    std::uint32_t ReadMemReg(cs_x86_op& op);
    std::uint32_t ReadReg(const std::string& regName);
};

std::string GetX86RegName(x86_reg reg);

class VmpUnicornContext
{
public:
    static std::unique_ptr<VmpUnicornContext> DefaultContext();
    static size_t DefaultEsp();
    void SetVmJmpVal(const std::string& reg_stack, size_t newVal);
	void FixVmJmpVal(const std::string& reg_stack, size_t newVal);
    void SetVmCodeVal(const std::string& reg_code, size_t newVal);
public:
    reg_context context;
    size_t stackCodeBase;
    std::vector<unsigned char> stackBuffer;
};