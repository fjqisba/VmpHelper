#include "PrintManager.h"
#include "../Ghidra/printc.hh"

PrintManager PrintManager::gPrintManager;

ghidra::PrintLanguage* PrintManager::GetDefaultPrintLanguage(ghidra::Architecture* glb)
{
	return new ghidra::PrintC(glb, "c-language");
}