#include "VmpArch.h"
#include "IDALoadImage.h"
#include "../Ghidra/libdecomp.hh"
#include "../Helper/IDAWrapper.h"
#include "../Helper/AsmBuilder.h"
#include "../Manager/exceptions.h"
#include "../GhidraExtension/VmpNode.h"
#include "../GhidraExtension/VmpControlFlow.h"
#include "../GhidraExtension/VmpFunction.h"
#include "../Ghidra/funcdata.hh"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

VmpArchitecture* gArch = nullptr;

VmpArchitecture::VmpArchitecture() :ghidra::SleighArchitecture("", "", 0x0)
{
    if (!initVmpArchitecture()) {
        throw Exception("InitVmpArchitecture error.");
    }
	ghidra::Sleigh* sleigh = (ghidra::Sleigh*)translate;

    gArch = this;
    if (arch_type == ARCH_X86) {
		for (unsigned int n = 0; n < 16; n++) {
			std::string vmRegName = "R" + std::to_string(n);
			ghidra::VarnodeData tmpVarnode;
			tmpVarnode.space = sleigh->getSpaceByName("register");
			tmpVarnode.offset = 0x10000 + (n * 4);
			tmpVarnode.size = 0x4;
			sleigh->varnode_xref[tmpVarnode] = vmRegName;

			ghidra::VarnodeSymbol* symbol = new ghidra::VarnodeSymbol(vmRegName, tmpVarnode.space, tmpVarnode.offset, 0x4);
			sleigh->symtab.getGlobalScope()->addSymbol(symbol);

			//µÍ1Î»
			symbol = new ghidra::VarnodeSymbol(vmRegName + "b", tmpVarnode.space, tmpVarnode.offset, 0x1);
			sleigh->symtab.getGlobalScope()->addSymbol(symbol);

			//µÍ2Î»
			symbol = new ghidra::VarnodeSymbol(vmRegName + "w", tmpVarnode.space, tmpVarnode.offset, 0x2);
			sleigh->symtab.getGlobalScope()->addSymbol(symbol);
		}
    }
}

VmpArchitecture::~VmpArchitecture()
{

}

VmpArchitecture::architecture_e VmpArchitecture::ArchType()
{
    return arch_type;
}

void VmpArchitecture::buildLoader(ghidra::DocumentStorage& store)
{
	collectSpecFiles(*errorstream);
	loader = new IDALoadImage(this);
}

void VmpArchitecture::resolveArchitecture(void)
{
    archid = getTarget();
    if (archid.find(':') == std::string::npos) {
        archid = loader->getArchType();
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
    if (archid == "x86:LE:32:default:windows") {
        arch_type = VmpArchitecture::ARCH_X86;
    }
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

ghidra::Funcdata* VmpArchitecture::AnaVmpFunction(VmpFunction* func)
{
	ghidra::Address startAddr(getDefaultCodeSpace(), func->startAddr);
	ghidra::Funcdata* fd = symboltab->getGlobalScope()->findFunction(startAddr);
	if (!fd) {
		fd = symboltab->getGlobalScope()->addFunction(startAddr, std::to_string(func->startAddr))->getFunction();
	}
	clearAnalysis(fd);
	fd->clearExtensionData();
	fd->followVmpFunction(func);
	ghidra::Action* rootAction = allacts.setCurrent("decompile");
	rootAction->reset(*fd);
	auto res = rootAction->perform(*fd);
	if (res < 0) {
		return nullptr;
	}
#ifdef DeveloperMode
	std::stringstream ss;
	fd->printRaw(ss);
	std::string rawResult = ss.str();
#endif
	return fd;
}

ghidra::Funcdata* VmpArchitecture::OptimizeBlock(ghidra::Funcdata* fd)
{
	ghidra::Action* rootAction = allacts.setCurrent("blockoptimize");
	rootAction->reset(*fd);
	auto res = rootAction->perform(*fd);
	if (res < 0) {
		return nullptr;
	}
#ifdef DeveloperMode
	std::stringstream ss;
	fd->printRaw(ss);
	std::string rawResult = ss.str();
#endif
	return fd;
}

ghidra::Funcdata* VmpArchitecture::AnaVmpBasicBlock(VmpBasicBlock* basicBlock)
{
	ghidra::Address startAddr(getDefaultCodeSpace(), 0x0);
	ghidra::Funcdata* fd = symboltab->getGlobalScope()->findFunction(startAddr);
	if (!fd) {
		fd = symboltab->getGlobalScope()->addFunction(startAddr, "")->getFunction();
	}
	clearAnalysis(fd);
	fd->clearExtensionData();
	fd->followVmpBasicBlock(basicBlock);
	ghidra::Action* rootAction = allacts.setCurrent("vmpblock");
	rootAction->reset(*fd);
	auto res = rootAction->perform(*fd);
	if (res < 0) {
		return nullptr;
	}
#ifdef DeveloperMode
	std::stringstream ss;
	fd->printRaw(ss);
	std::string rawResult = ss.str();
#endif
	return fd;
}

ghidra::Funcdata* VmpArchitecture::AnaVmpHandler(VmpNode* nodeInput)
{
    //²âÊÔ´úÂë
    if (nodeInput->addrList[0] == 0x00ceef83) {
        int a = 0;
    }
    ghidra::Address startAddr(getDefaultCodeSpace(), 0x0);
    ghidra::Funcdata* fd = symboltab->getGlobalScope()->findFunction(startAddr);
    if (!fd) {
        fd = symboltab->getGlobalScope()->addFunction(startAddr, "")->getFunction();
    }
    clearAnalysis(fd);
    fd->clearExtensionData();
    fd->followVmpNode(nodeInput);
    ghidra::Action* rootAction = allacts.setCurrent("vmphandler");
    rootAction->reset(*fd);
    auto res = rootAction->perform(*fd);
    if (res < 0) {
        return nullptr;
    }
#ifdef DeveloperMode
    std::stringstream ss;
    fd->printRaw(ss);
    std::string rawResult = ss.str();
#endif
    return fd;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif