#pragma once
#include "../Ghidra/sleigh_arch.hh"

namespace ghidra
{
	class Funcdata;
}

class VmpNode;

class VmpArchitecture :public ghidra::SleighArchitecture
{
public:
	VmpArchitecture();
	~VmpArchitecture();
public:
	ghidra::Funcdata* AnaVmpHandler(VmpNode* nodeInput);
protected:
	void buildLoader(ghidra::DocumentStorage& store) override;
	void resolveArchitecture(void) override;
private:
	bool initVmpArchitecture();
};