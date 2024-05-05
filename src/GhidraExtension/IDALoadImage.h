#pragma once
#include "../Ghidra/loadimage.hh"

class VmpArchitecture;

class IDALoadImage:public ghidra::LoadImage
{
public:
	IDALoadImage(VmpArchitecture*);
	~IDALoadImage();
private:
	void loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr) override;
	std::string getArchType(void) const override;
	void adjustVma(long adjust) override;
	void getReadonly(ghidra::RangeList& list) const override;
private:
	VmpArchitecture* arch;
};