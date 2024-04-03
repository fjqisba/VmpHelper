#pragma once
#include "../Ghidra/loadimage.hh"

class IDALoadImage:public ghidra::LoadImage
{
public:
	IDALoadImage();
	~IDALoadImage();
private:
	void loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr) override;
	std::string getArchType(void) const override;
	void adjustVma(long adjust) override;
};