#include "IDALoadImage.h"
#include "../Helper/IDAWrapper.h"
#include "VmpArch.h"
#include <segment.hpp>

IDALoadImage::IDALoadImage(VmpArchitecture* glb) :ghidra::LoadImage("image")
{
	arch = glb;
}

IDALoadImage::~IDALoadImage()
{

}

void IDALoadImage::loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr)
{
   IDAWrapper::get_bytes(ptr, size, addr.getOffset(), 0x1);
}

std::string IDALoadImage::getArchType(void)const
{
    if (IDAWrapper::is64BitProgram()) {
        return "pei-x86-64";
    }
    return "pe-i386";
}

void IDALoadImage::adjustVma(long adjust)
{

}

void IDALoadImage::getReadonly(ghidra::RangeList& list) const
{
	int segCount = get_segm_qty();
	for (int idx = 0; idx < segCount; ++idx)
	{
		segment_t* pSegment = getnseg(idx);
		if (pSegment->perm & SEGPERM_EXEC) {
			continue;
		}
		if (pSegment->perm & SEGPERM_WRITE) {
			continue;
		}
		if (pSegment->perm & SEGPERM_READ) {
			list.insertRange(arch->getSpaceByName("const"), pSegment->start_ea, pSegment->end_ea - 1);
		}
	}
}