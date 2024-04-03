#include "VmpArch.h"
#include "IDALoadImage.h"
#include "../Ghidra/libdecomp.hh"
#include "../Helper/IDAWrapper.h"

VmpArchitecture::VmpArchitecture() :ghidra::SleighArchitecture("", "", 0x0)
{

}

VmpArchitecture::~VmpArchitecture()
{

}

void VmpArchitecture::buildLoader(ghidra::DocumentStorage& store)
{
	collectSpecFiles(*errorstream);
	loader = new IDALoadImage();
}

void VmpArchitecture::resolveArchitecture(void)
{
    archid = getTarget();
    if (archid.find(':') == std::string::npos) {
        archid = loader->getArchType();
        // kludge to distinguish windows binaries from linux/gcc
        if (archid.find("efi-app-ia32") != std::string::npos)
            archid = "x86:LE:32:default:windows";
        else if (archid.find("pe-i386") != std::string::npos)
            archid = "x86:LE:32:default:windows";
        else if (archid.find("pei-i386") != std::string::npos)
            archid = "x86:LE:32:default:windows";
        else if (archid.find("pei-x86-64") != std::string::npos)
            archid = "x86:LE:64:default:windows";
        else if (archid.find("sparc") != std::string::npos)
            archid = "sparc:BE:32:default:default";
        else if (archid.find("elf64") != std::string::npos)
            archid = "x86:LE:64:default:gcc";
        else if (archid.find("elf") != std::string::npos)
            archid = "x86:LE:32:default:gcc";
        else if (archid.find("mach-o") != std::string::npos)
            archid = "PowerPC:BE:32:default:macosx";
        else
            throw ghidra::LowlevelError("Cannot convert bfd target to sleigh target: " + archid);
    }
    SleighArchitecture::resolveArchitecture();
}

bool VmpArchitecture::initVmpArchitecture()
{
    std::string ghidraroot = IDAWrapper::idadir("plugins") + "\\Ghidra";
    std::vector<std::string> extrapaths;
    ghidra::startDecompilerLibrary(ghidraroot.c_str(), extrapaths);
    std::string errmsg;
    bool iserror = false;
    ghidra::DocumentStorage store;	// temporary storage for xml docs
    try {
        this->init(store);
    }
    catch (ghidra::DecoderError& err) {
        errmsg = err.explain;
        iserror = true;
    }
    catch (ghidra::LowlevelError& err) {
        errmsg = err.explain;
        iserror = true;
    }
    if (iserror) {
        return false;
    }

    return true;
}
