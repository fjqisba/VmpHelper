#pragma once
#include "../Ghidra/sleigh_arch.hh"

namespace ghidra
{
	class Funcdata;
}

class VmpNode;
class VmpBasicBlock;



class VmpArchitecture :public ghidra::SleighArchitecture
{
public:
	enum architecture_e
	{
		ARCH_INVALID = 0x0,
		ARCH_X86,
		ARCH_X86_64,
	};
public:
	VmpArchitecture();
	~VmpArchitecture();
public:
	architecture_e ArchType();
	ghidra::Funcdata* AnaVmpHandler(VmpNode* nodeInput);
	ghidra::Funcdata* AnaVmpBasicBlock(VmpBasicBlock* basicBlock);
protected:
	void buildLoader(ghidra::DocumentStorage& store) override;
	void resolveArchitecture(void) override;
private:
	bool initVmpArchitecture();
private:
	architecture_e arch_type;
};

extern VmpArchitecture* gArch;
