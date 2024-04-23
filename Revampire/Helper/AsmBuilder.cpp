#include "AsmBuilder.h"

AsmBuilder::AsmBuilder()
{

}

AsmBuilder::~AsmBuilder()
{

}

AsmBuilder& AsmBuilder::X86()
{
	static AsmBuilder gAsmBuilderX86;
	return gAsmBuilderX86;
}