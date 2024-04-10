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
	VmpArchitecture();
	~VmpArchitecture();
public:
	ghidra::Funcdata* AnaVmpHandler(VmpNode* nodeInput);
	ghidra::Funcdata* AnaVmpBasicBlock(VmpBasicBlock* basicBlock);
protected:
	void buildLoader(ghidra::DocumentStorage& store) override;
	void resolveArchitecture(void) override;
private:
	bool initVmpArchitecture();
};