#include "IDALoadImage.h"
#include "../Helper/IDAWrapper.h"

IDALoadImage::IDALoadImage() :ghidra::LoadImage("image")
{

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