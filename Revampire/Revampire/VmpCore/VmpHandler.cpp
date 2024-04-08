#include "VmpHandler.h"
#include <map>
#include "VmpReEngine.h"
#include "../Ghidra/funcdata.hh"
#include "../Helper/GhidraHelper.h"
#include "../Manager/exceptions.h"
#include "../GhidraExtension/VmpArch.h"
#include "../GhidraExtension/VmpControlFlow.h"
#include "../GhidraExtension/VmpInstruction.h"

VmpHandlerRange::VmpHandlerRange(VmpNode& nodeInput)
{
    startAddr = nodeInput.addrList[0];
    endAddr = nodeInput.addrList[nodeInput.addrList.size() - 1];
    hash = NodeHash(nodeInput);
}

std::uint64_t VmpHandlerRange::NodeHash(VmpNode& nodeInput)
{
    std::uint64_t hash = nodeInput.addrList.size();
    for (unsigned int n = 0; n < nodeInput.addrList.size(); ++n) {
        hash ^= (nodeInput.addrList[n] * 0x10001);
        hash = hash << 0x5;
    }
    return hash;
}


VmpHandlerFactory::VmpHandlerFactory(VmpArchitecture* re)
{
	arch = re;
}

bool VmpHandlerFactory::tryMatch_vPopReg(std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult)
{
	//满足的条件是
	//srcResult来源于vmStack
	if (srcResult.size() != 1) {
		return false;
	}
	//srcResult来源于内存访问
	if (!srcResult[0].bAccessMem) {
		return false;
	}
	const std::string& vmStackReg = srcResult[0].name;
	std::string vmCodeReg;
	bool bContainEsp = false;
	bool bContainVmCode = false;
	for (unsigned int n = 0; n < dstResult.size(); ++n) {
		if (dstResult[n].name == "ESP" && !dstResult[n].bAccessMem) {
			bContainEsp = true;
		}
		else if (dstResult[n].bAccessMem && dstResult[n].name != vmStackReg) {
			bContainVmCode = true;
			vmCodeReg = dstResult[n].name;
		}
	}
	if (!bContainEsp || !bContainVmCode) {
		return false;
	}
	if (!buildContext->vmReg.isSelected) {
		buildContext->vmReg.vmCodeReg = vmCodeReg;
		buildContext->vmReg.vmStackReg = vmStackReg;
		buildContext->vmReg.isSelected = true;
	}
	return true;
}

bool VmpHandlerFactory::Execute_FINISH_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd)
{
	auto itBegin = fd->beginOp(ghidra::CPUI_STORE);
	auto itEnd = fd->endOp(ghidra::CPUI_STORE);
	while (itBegin != itEnd) {
		ghidra::PcodeOp* opStore = *itBegin++;
		GhidraHelper::PcodeOpTracer opTracer(fd);
		auto dstResult = opTracer.TraceInput(opStore->getAddr().getOffset(), opStore->getIn(1));
		auto srcResult = opTracer.TraceInput(opStore->getAddr().getOffset(), opStore->getIn(2));
		if (tryMatch_vPopReg(dstResult, srcResult)) {
			std::unique_ptr<VmpOpPopReg> vPopRegOp = std::make_unique<VmpOpPopReg>();
			
		}
		int a = 0;
	}
	return true;
}

bool VmpHandlerFactory::Execute_FIND_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd)
{
	std::map<int, ghidra::VarnodeData> storeContextMap;
	ghidra::BlockBasic* bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return false;
	}
	ghidra::AddrSpace* stackspace = fd->getArch()->getStackSpace();
	auto itBegin = bb->beginOp();
	auto itEnd = bb->endOp();
	while (itBegin != itEnd) {
		ghidra::PcodeOp* curOp = *itBegin++;
		ghidra::Varnode* vOut = curOp->getOut();
		if (!vOut) {
			continue;
		}
		if (vOut->getSpace() != stackspace) {
			continue;
		}
		ghidra::VarnodeData storeData;
		int stackOff = vOut->getAddr().getOffset();
		if (curOp->code() == ghidra::CPUI_COPY) {
			ghidra::Varnode* inputNode = curOp->getIn(0);
			if (inputNode->isConstant()) {
				storeData.space = inputNode->getSpace();
				storeData.offset = inputNode->getOffset();
				storeData.size = inputNode->getSize();
				storeContextMap[stackOff] = storeData;
			}
			else if (inputNode->getSpace()->getName() == "register") {
				storeData.space = inputNode->getSpace();
				storeData.offset = inputNode->getOffset();
				storeData.size = inputNode->getSize();
				storeContextMap[stackOff] = storeData;
			}
		}
	}
	if (storeContextMap.size() < 11) {
		return false;
	}
	//将map转换为vector
	std::unique_ptr<VmpOpInit> opInitVm = std::make_unique<VmpOpInit>();
	int startEsp = -4;
	int maxEspOffset = storeContextMap.begin()->first;
	while (startEsp >= maxEspOffset) {
		auto it = storeContextMap.find(startEsp);
		if (it == storeContextMap.end()) {
			return false;
		}
		else {
			opInitVm->storeContext.push_back(it->second);
		}
		startEsp = startEsp - 4;
	}
	opInitVm->addr = VmAddress(nodeInput.addrList[0], 0x0);
	buildContext->bBlock->insList.push_back(std::move(opInitVm));
	buildContext->status = VmpBlockBuildContext::FINISH_VM_INIT;
	buildContext->ret = VmpBlockBuildContext::BUILD_CONTINUE;
	return true;
}


bool VmpHandlerFactory::BuildVmpBlock(VmpBlockBuildContext* buildData, VmpBlockWalker& walker)
{
	this->buildContext = buildData;
	VmpNode currentNode;
	while (!walker.IsWalkToEnd()) {
		VmpNode tmpNode = walker.GetNextNode();
		if (!tmpNode.addrList.size()) {
			return false;
		}
		currentNode.append(tmpNode);
		ExecuteVmpPattern(currentNode);
		if (buildData->ret == VmpBlockBuildContext::BUILD_EXIT) {
			break;
		}
		else if (buildData->ret == VmpBlockBuildContext::BUILD_CONTINUE) {
			currentNode.clear();
		}
		walker.MoveToNext();
	}
    return true;
}

void VmpHandlerFactory::ExecuteVmpPattern(VmpNode& nodeInput)
{
    ghidra::Funcdata* fd = arch->AnaVmpHandler(&nodeInput);
    if (fd == nullptr) {
        throw GhidraException("ana vmp handler error");
    }
	switch (buildContext->status)
	{
    case VmpBlockBuildContext::FIND_VM_INIT:
	{
		if (!Execute_FIND_VM_INIT(nodeInput,fd)) {
			buildContext->ret = VmpBlockBuildContext::BUILD_MERGE;
		}
		break;
	}
    case VmpBlockBuildContext::FINISH_VM_INIT:
		Execute_FINISH_VM_INIT(nodeInput, fd);
		break;
	}
	return;
}