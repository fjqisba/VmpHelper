#pragma once
#include "../Ghidra/printlanguage.hh"

class PrintManager
{
public:
	static PrintManager gPrintManager;			///< The singleton instance
	ghidra::PrintLanguage* GetDefaultPrintLanguage(ghidra::Architecture* glb);
};