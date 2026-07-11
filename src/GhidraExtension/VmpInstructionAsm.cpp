#include "VmpInstruction.h"
#include "../Helper/AsmBuilder.h"
#include "../Helper/GhidraHelper.h"
#include "../Manager/exceptions.h"
#include "VmpArch.h"

void VmpInstruction::BuildX86Asm(triton::Context* ctx)
{

	return;
}

void VmpOpInit::BuildX86Asm(triton::Context* ctx)
{
	//X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//for (const auto& context : storeContext) {
	//	if (context.getAddr().getSpace()->getName() == "const") {
	//		auto asmRet = x86Asm.push_const(context.getAddr().getOffset());
	//		triton::arch::Instruction tmpInst(addr.vmdata, asmRet->encode, asmRet->encode_size);
	//		ctx->processing(tmpInst);
	//	}
	//	else if (context.getAddr().getSpace()->getName() == "register") {
	//		std::string regName = GhidraHelper::GetVarnodeRegName(context);
	//		auto asmRet = x86Asm.push_reg(regName);
	//		triton::arch::Instruction tmpInst(addr.vmdata, asmRet->encode, asmRet->encode_size);
	//		ctx->processing(tmpInst);
	//	}
	//}
	return;
}

void VmpOpExit::BuildX86Asm(triton::Context* ctx)
{
	//X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//for (unsigned int n = 0; n < exitContext.size(); ++n) {
	//	std::string regName = GhidraHelper::GetVarnodeRegName(exitContext[n]);
	//	if (regName == "EIP" || regName == "ESP") {
	//		continue;
	//	}
	//	auto asmRet = x86Asm.pop_reg(regName);
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//}
	//std::string asmStr = "ret";
	//auto asmRet = x86Asm.EncodeAsm(0x0, asmStr);
	//ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	return;
}

void VmpOpPopReg::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	std::string asmStr = "pop dword ptr ds:[" + std::to_string(vmRegOffset) + "]";
	//	auto asmRet = x86Asm.EncodeAsm(0x0, asmStr);
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	//if (opSize == 0x2) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov ax,word ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "lea esp,[esp + 0x2]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov word ptr[" + std::to_string(vmRegOffset) + "],ax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	return;
}

void VmpOpNand::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov eax, dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov ecx, dword ptr[esp + 0x4]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "not eax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "not ecx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "or eax,ecx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov dword ptr[esp+0x4], eax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pushfd");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pop dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
}

void VmpOpNor::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov eax, dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov ecx, dword ptr[esp + 0x4]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "not eax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "not ecx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "and eax,ecx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov dword ptr[esp+0x4], eax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pushfd");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pop dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}

	return;
}

void VmpOpShr::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	/*if (opSize == 0x4) {
		auto asmRet = x86Asm.EncodeAsm(0x0, "mov eax, dword ptr[esp]");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

		asmRet = x86Asm.EncodeAsm(0x0, "mov cl, byte ptr[esp + 0x4]");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

		asmRet = x86Asm.EncodeAsm(0x0, "lea esp,[esp - 0x2]");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

		asmRet = x86Asm.EncodeAsm(0x0, "shr eax, cl");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

		asmRet = x86Asm.EncodeAsm(0x0, "mov dword ptr[esp+0x4], eax");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

		asmRet = x86Asm.EncodeAsm(0x0, "pushfd");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

		asmRet = x86Asm.EncodeAsm(0x0, "pop dword ptr[esp]");
		ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
		return;
	}*/
}

void VmpOpPushReg::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	std::string asmStr = "push dword ptr ds:[" + std::to_string(vmRegOffset) + "]";
	//	auto asmRet = x86Asm.EncodeAsm(0x0, asmStr);
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	//if (opSize == 0x2) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov cx,word ptr[" + std::to_string(vmRegOffset) + "]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "lea esp,[esp - 0x2]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov word ptr[esp],cx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	return;
}

void VmpOpPushImm::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	auto asmRet = x86Asm.push_const(immVal);
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	//if(opSize == 0x2){
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "lea esp,[esp-0x2]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov word ptr[esp]," + std::to_string(immVal));
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	//throw AsmBuilderException("need fix");
	return;
}

void VmpOpJmp::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//std::string asmStr = "ret";
	//auto asmRet = x86Asm.EncodeAsm(0x0, asmStr);
	//triton::arch::Instruction tmpInst(addr.vmdata, asmRet->encode, asmRet->encode_size);
	//ctx->processing(tmpInst);
	return;
}

void VmpOpPushVSP::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//std::string asmStr = "push esp";
	//auto asmRet = x86Asm.EncodeAsm(0x0, asmStr);
	//ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	return;
}

void VmpOpAdd::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov edx,dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov ecx,dword ptr[esp + 0x4]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "add edx, ecx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov dword ptr[esp+0x4], edx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pushfd");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pop dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}
	//if (opSize == 0x2) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov dx,word ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov ax,word ptr[esp + 0x2]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "lea esp,[esp - 0x2]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "add dx, ax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov word ptr[esp+0x4], dx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pushfd");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "pop dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//	return;
	//}

}

void VmpOpWriteVSP::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();

	//auto asmRet = x86Asm.EncodeAsm(0x0, "mov esp,[esp]");
	//ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	return;
}

void VmpOpReadMem::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov eax,dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov ecx,dword ptr[eax]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov dword ptr[esp], ecx");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//}
}

void VmpOpWriteMem::BuildX86Asm(triton::Context* ctx)
{
	X86AsmBuilder& x86Asm = AsmBuilder::X86();
	//if (opSize == 0x4) {
	//	auto asmRet = x86Asm.EncodeAsm(0x0, "mov ecx,dword ptr[esp]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov eax,dword ptr[esp + 0x4]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "mov dword ptr[ecx], eax");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));

	//	asmRet = x86Asm.EncodeAsm(0x0, "lea esp,[esp + 0x8]");
	//	ctx->processing(triton::arch::Instruction(addr.vmdata, asmRet->encode, asmRet->encode_size));
	//}
}