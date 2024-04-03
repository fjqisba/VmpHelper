#pragma once
#include "../Ghidra/sleigh_arch.hh"

//当前仅支持32位

class VmpArchitecture :public ghidra::SleighArchitecture
{
public:
	VmpArchitecture();
	~VmpArchitecture();
	bool initVmpArchitecture();
protected:
	void buildLoader(ghidra::DocumentStorage& store) override;
	void resolveArchitecture(void) override;
private:

};