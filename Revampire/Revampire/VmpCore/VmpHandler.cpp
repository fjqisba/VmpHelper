#include "VmpHandler.h"
#include <map>
#include "VmpReEngine.h"
#include "../Ghidra/funcdata.hh"
#include "../Helper/GhidraHelper.h"
#include "../Manager/exceptions.h"
#include "../GhidraExtension/VmpArch.h"
#include "../GhidraExtension/VmpControlFlow.h"
#include "../GhidraExtension/VmpInstruction.h"

size_t GetMemAccessSize(size_t addr)
{
	auto asmData = DisasmManager::Main().DecodeInstruction(addr);
	cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
	if (op1.type == X86_OP_MEM) {
		return op1.size;
	}
	return 0x0;
}

void VmpRegStatus::ClearStatus()
{
	isSelected = false;
	reg_code = "";
	reg_stack = "";
}

VmpBlockBuildContext::VmpBlockBuildContext()
{

}

bool VmpBlockBuildContext::PushVmpOp(std::unique_ptr<VmpInstruction> inst)
{
	if (inst->opType == VM_JMP) {
		from_addr = inst->addr;
	}
	newBlock->insList.push_back(std::move(inst));
	return true;
}

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

bool VmpHandlerFactory::tryMatch_vJmp(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 0 || !loadCount) {
		return false;
	}
	auto itLoad = fd->obank.loadlist.begin();
	//vJmp
	//0 : u0x00007a00(0x004ad3c2:0) = *(ram, EBP(i))
	//1 : EDX(0x004ad3c2:1) = u0x00007a00(0x004ad3c2:0)
	//2 : EBP(0x004ad3c9:42) = EBP(i) + #0x1(*#0x4)
	//3 : ESI(0x004ad3d4:35) = u0x00007a00(0x004ad3c2:0)
	//4 : EDI(0x004ad3d8:37) = EBP(0x004ad3c9:42)
	//5 : EIP(0x004bea62:39) = #0x460fe4
	if (loadCount == 0x1) {
		ghidra::PcodeOp* loadOp1 = *itLoad++;
		ghidra::Varnode* vLoadReg = loadOp1->getIn(1);
		std::string loadRegName = fd->getArch()->translate->getRegisterName(vLoadReg->getSpace(), vLoadReg->getOffset(), vLoadReg->getSize());
		if (loadRegName != buildContext->vmreg.reg_stack) {
			return false;
		}
		std::unique_ptr<VmpOpJmp> vJmpOp = std::make_unique<VmpOpJmp>();
		vJmpOp->addr = nodeInput.readVmAddress(buildContext->vmreg.reg_code);
		buildContext->PushVmpOp(std::move(vJmpOp));
		buildContext->vmreg.ClearStatus();
		buildContext->build_ret = VmpBlockBuildContext::BUILD_EXIT;
		return true;
	}
	else if (loadCount == 0x2) {
		ghidra::PcodeOp* loadOp1 = *itLoad++;
		ghidra::PcodeOp* loadOp2 = *itLoad++;
		ghidra::Varnode* vLoadReg = loadOp1->getIn(1);
		std::string loadRegName = fd->getArch()->translate->getRegisterName(vLoadReg->getSpace(), vLoadReg->getOffset(), vLoadReg->getSize());
		if (loadRegName != buildContext->vmreg.reg_stack) {
			return false;
		}
		GhidraHelper::PcodeOpTracer opTracer(fd);
		auto srcResult = opTracer.TraceInput(loadOp2->getAddr().getOffset(), loadOp2->getIn(1));
		if (srcResult.size() != 1) {
			return false;
		}
		if (!srcResult[0].bAccessMem || srcResult[0].name != buildContext->vmreg.reg_stack) {
			return false;
		}
		std::unique_ptr<VmpOpJmp> vJmpOp = std::make_unique<VmpOpJmp>();
		vJmpOp->addr = nodeInput.readVmAddress(buildContext->vmreg.reg_code);
		buildContext->PushVmpOp(std::move(vJmpOp));
		buildContext->vmreg.ClearStatus();
		buildContext->build_ret = VmpBlockBuildContext::BUILD_EXIT;
		return true;
	}
	return false;
}

bool VmpHandlerFactory::tryMatch_vCheckEsp(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount || loadCount) {
		return false;
	}
	auto itBegin = fd->beginOpAll();
	auto itEnd = fd->endOpAll();
	while (itBegin != itEnd) {
		ghidra::PcodeOp* curOp = itBegin->second;
		itBegin++;
		if (curOp->code() == ghidra::CPUI_PTRSUB) {
			ghidra::Varnode* firstVn = curOp->getIn(0);
			std::string regName = fd->getArch()->translate->getRegisterName(firstVn->getSpace(), firstVn->getOffset(), firstVn->getSize());
			if (firstVn->isInput() && regName == "ESP") {
				std::unique_ptr<VmpOpCheckEsp> vCheckEsp = std::make_unique<VmpOpCheckEsp>();
				vCheckEsp->addr.raw = nodeInput.addrList[0];
				vCheckEsp->addr.vmdata = nodeInput.contextList[0].ReadReg(buildContext->vmreg.reg_code);
				buildContext->PushVmpOp(std::move(vCheckEsp));
				buildContext->build_ret = VmpBlockBuildContext::BUILD_CONTINUE;
				return true;
			}
		}
	}
	return false;
}

ghidra::OpCode CheckLogicPattern(ghidra::PcodeOp* startOP)
{
	std::vector<ghidra::PcodeOp*> checkList;
	checkList.push_back(startOP);
	while (!checkList.empty()) {
		ghidra::PcodeOp* curOp = checkList.back();
		checkList.pop_back();
		if (curOp == nullptr) {
			continue;
		}
		//递归模板
		switch (curOp->code()) {
		case ghidra::CPUI_INT_ZEXT:
		case ghidra::CPUI_SUBPIECE:
			checkList.push_back(curOp->getIn(0)->getDef());
			break;
		case ghidra::CPUI_PIECE:
			checkList.push_back(curOp->getIn(0)->getDef());
			checkList.push_back(curOp->getIn(1)->getDef());
			break;
		}
		//匹配模板
		if (curOp->code() == ghidra::CPUI_INT_LEFT) {
			ghidra::PcodeOp* defOp1 = curOp->getIn(0)->getDef();
			if (defOp1 && defOp1->code() == ghidra::CPUI_LOAD) {
				return ghidra::CPUI_INT_LEFT;
			}
		}
		else if (curOp->code() == ghidra::CPUI_INT_RIGHT) {
			ghidra::PcodeOp* defOp1 = curOp->getIn(0)->getDef();
			if (defOp1 && defOp1->code() == ghidra::CPUI_LOAD) {
				return ghidra::CPUI_INT_RIGHT;
			}
		}
		else if (curOp->code() == ghidra::CPUI_INT_ADD) {
			ghidra::PcodeOp* defOp1 = curOp->getIn(0)->getDef();
			ghidra::PcodeOp* defOp2 = curOp->getIn(1)->getDef();
			if (defOp1 && defOp2 && defOp1->code() == ghidra::CPUI_LOAD && defOp2->code() == ghidra::CPUI_LOAD) {
				return ghidra::CPUI_INT_ADD;
			}
		}
		else if (curOp->code() == ghidra::CPUI_INT_AND) {
			if (curOp->getIn(1)->isConstant()) {
				checkList.push_back(curOp->getIn(0)->getDef());
				continue;
			}
			ghidra::PcodeOp* defOp1 = curOp->getIn(0)->getDef();
			ghidra::PcodeOp* defOp2 = curOp->getIn(1)->getDef();
			if (defOp1 && defOp2 && defOp1->code() == ghidra::CPUI_INT_NEGATE && defOp2->code() == ghidra::CPUI_INT_NEGATE) {
				return ghidra::CPUI_INT_AND;
			}
		}
		else if (curOp->code() == ghidra::CPUI_INT_OR) {
			ghidra::PcodeOp* defOp1 = curOp->getIn(0)->getDef();
			ghidra::PcodeOp* defOp2 = curOp->getIn(1)->getDef();
			if (defOp1 && defOp2 && defOp1->code() == ghidra::CPUI_INT_NEGATE && defOp2->code() == ghidra::CPUI_INT_NEGATE) {
				return ghidra::CPUI_INT_OR;
			}
		}
	}
	return ghidra::OpCode(0x0);
}


bool VmpHandlerFactory::tryMatch_vLogicalOp(ghidra::Funcdata* fd, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult)
{
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
		return false;
	}
	if (dstResult[0].name != buildContext->vmreg.reg_stack) {
		return false;
	}
	//src全部来源于stack
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (!srcResult[n].bAccessMem) {
			return false;
		}
		if (srcResult[n].name != buildContext->vmreg.reg_stack) {
			return false;
		}
	}
	size_t storeCount = fd->obank.storelist.size();
	if (storeCount != 2) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp1 = *itStore++;
	ghidra::PcodeOp* storeOp2 = *itStore++;
	ghidra::PcodeOp* loadOp1 = *itLoad++;
	ghidra::OpCode logicCode = CheckLogicPattern(storeOp1->getIn(2)->getDef());

	VmAddress vmAddr;
	vmAddr.raw = nodeInput.addrList[0];
	vmAddr.vmdata = nodeInput.contextList[0].ReadReg(buildContext->vmreg.reg_code);
	if (logicCode == ghidra::CPUI_INT_ADD) {
		std::unique_ptr<VmpOpAdd> vAddOp = std::make_unique<VmpOpAdd>();
		vAddOp->addr = vmAddr;
		vAddOp->opSize = GetMemAccessSize(loadOp1->getAddr().getOffset());
		buildContext->PushVmpOp(std::move(vAddOp));
		buildContext->build_ret = VmpBlockBuildContext::BUILD_CONTINUE;
		return true;
	}
	return false;
}

bool VmpHandlerFactory::tryMatch_vPushReg(ghidra::Funcdata* fd, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult)
{
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
		return false;
	}
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount < 1 || loadCount < 3) {
		return false;
	}
	bool bContainEsp = false;
	bool bContainVmCode = false;
	size_t loadEspAddr = 0x0;
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (srcResult[n].name == "ESP" && srcResult[n].bAccessMem) {
			bContainEsp = true;
			loadEspAddr = srcResult[n].addr;
		}
		else if (srcResult[n].name == buildContext->vmreg.reg_code && srcResult[n].bAccessMem) {
			bContainVmCode = true;
		}
	}
	if (!bContainEsp || !bContainVmCode) {
		return false;
	}
	std::unique_ptr<VmpOpPushReg> vPushRegOp = std::make_unique<VmpOpPushReg>();
	vPushRegOp->addr = nodeInput.readVmAddress(buildContext->vmreg.reg_code);
	vPushRegOp->opSize = GetMemAccessSize(loadEspAddr);
	for (unsigned int n = 0; n < nodeInput.contextList.size(); ++n) {
		reg_context& tmpContext = nodeInput.contextList[n];
		if (tmpContext.EIP == loadEspAddr) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
			if (op1.type == X86_OP_MEM) {
				vPushRegOp->vmRegOffset = tmpContext.ReadMemReg(op1);
				buildContext->PushVmpOp(std::move(vPushRegOp));
				buildContext->build_ret = VmpBlockBuildContext::BUILD_CONTINUE;
				return true;
			}
		}
	}
	return false;
}

bool VmpHandlerFactory::tryMatch_vPushImm(ghidra::Funcdata* fd, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult)
{
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
		return false;
	}
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount < 1 || loadCount < 2) {
		return false;
	}
	const std::string& vmStackReg = dstResult[0].name;
	if (buildContext->vmreg.reg_stack != vmStackReg) {
		return false;
	}
	bool bOnlyFromVmCode = true;
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (srcResult[n].bAccessMem) {
			if (srcResult[n].name != buildContext->vmreg.reg_code) {
				bOnlyFromVmCode = false;
				break;
			}
		}
	}
	if (!bOnlyFromVmCode) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp = *itStore;
	ghidra::PcodeOp* loadOp = *itLoad;
	std::unique_ptr<VmpOpPushImm> vPushImm = std::make_unique<VmpOpPushImm>();
	vPushImm->addr = nodeInput.readVmAddress(buildContext->vmreg.reg_code);
	vPushImm->opSize = GetMemAccessSize(loadOp->getAddr().getOffset());
	for (unsigned int n = 0; n < nodeInput.contextList.size(); ++n) {
		reg_context& tmpContext = nodeInput.contextList[n];
		if (tmpContext.EIP == storeOp->getAddr().getOffset()) {
			auto tmpIns = DisasmManager::Main().DecodeInstruction(storeOp->getAddr().getOffset());
			cs_x86_op& op0 = tmpIns->raw->detail->x86.operands[0];
			cs_x86_op& op1 = tmpIns->raw->detail->x86.operands[1];
			if (op0.type == X86_OP_MEM && op1.type == X86_OP_REG) {
				vPushImm->immVal = tmpContext.ReadReg(op1.reg);
				buildContext->PushVmpOp(std::move(vPushImm));
				buildContext->build_ret = VmpBlockBuildContext::BUILD_CONTINUE;
				return true;
			}
		}
	}
	return false;
}

bool VmpHandlerFactory::tryMatch_vPopReg(ghidra::PcodeOp* opStore, VmpNode& nodeInput, std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult)
{
	//srcResult来源于vmStack
	if (srcResult.size() != 1) {
		return false;
	}
	//srcResult来源于内存访问
	if (!srcResult[0].bAccessMem) {
		return false;
	}
	const std::string& vmStackReg = srcResult[0].name;
	bool bContainEsp = false;
	GhidraHelper::TraceResult vmCodeTraceResult;
	for (unsigned int n = 0; n < dstResult.size(); ++n) {
		if (dstResult[n].name == "ESP" && !dstResult[n].bAccessMem) {
			bContainEsp = true;
		}
		else if (dstResult[n].bAccessMem && dstResult[n].name != vmStackReg) {
			vmCodeTraceResult = dstResult[n];
		}
	}
	if (!bContainEsp || vmCodeTraceResult.name.empty()) {
		return false;
	}
	if (!buildContext->vmreg.isSelected) {
		buildContext->vmreg.reg_code = vmCodeTraceResult.name;
		buildContext->vmreg.reg_stack = vmStackReg;
		buildContext->vmreg.isSelected = true;
	}
	else {
		if (buildContext->vmreg.reg_code != vmCodeTraceResult.name) {
			return false;
		}
		if (buildContext->vmreg.reg_stack != vmStackReg) {
			return false;
		}
	}
	std::unique_ptr<VmpOpPopReg> vPopRegOp = std::make_unique<VmpOpPopReg>();
	vPopRegOp->addr = nodeInput.readVmAddress(buildContext->vmreg.reg_code);
	vPopRegOp->opSize = GetMemAccessSize(srcResult[0].addr);
	for (unsigned int n = 0; n < nodeInput.contextList.size(); ++n) {
		reg_context& tmpContext = nodeInput.contextList[n];
		if (tmpContext.EIP == vPopRegOp->addr.raw) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			if (asmData->raw->id == X86_INS_MOV || asmData->raw->id == X86_INS_MOVZX || asmData->raw->id == X86_INS_MOVSX) {
				cs_x86_op& op0 = asmData->raw->detail->x86.operands[0];
				vPopRegOp->vmRegOffset = tmpContext.ReadMemReg(op0);
				buildContext->PushVmpOp(std::move(vPopRegOp));
				buildContext->build_ret = VmpBlockBuildContext::BUILD_CONTINUE;
				return true;
			}
		}
	}
	return false;
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
		if (tryMatch_vPopReg(opStore, nodeInput, dstResult, srcResult)) {
			return true;
		}
		if (tryMatch_vPushImm(fd, nodeInput, dstResult, srcResult)) {
			return true;
		}
		if (tryMatch_vPushReg(fd, nodeInput, dstResult, srcResult)) {
			return true;
		}
		if (tryMatch_vLogicalOp(fd, nodeInput, dstResult, srcResult)) {
			return true;
		}
		int a = 0;
	}
	if (tryMatch_vJmp(fd,nodeInput)) {
		return true;
	}
	if (tryMatch_vCheckEsp(fd, nodeInput)) {
		return true;
	}
	return true;
}

bool VmpHandlerFactory::Execute_FIND_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd)
{
	std::map<int, ghidra::VarnodeData> storeContextMap;
	const ghidra::BlockGraph& graph(fd->getBasicBlocks());
	ghidra::AddrSpace* stackspace = fd->getArch()->getStackSpace();
	for (unsigned int i = 0; i < graph.getSize(); ++i) {
		ghidra::BlockBasic* bb = (ghidra::BlockBasic*)graph.getBlock(i);
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
	}
	if (storeContextMap.size() < 11) {
		return false;
	}
	//将map转换为vector
	std::unique_ptr<VmpOpInit> opInitVm = std::make_unique<VmpOpInit>();
	int startEsp = -4;
	for (unsigned int n = 0; n < 11; ++n) {
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
	buildContext->PushVmpOp(std::move(opInitVm));
	buildContext->status = VmpBlockBuildContext::FINISH_VM_INIT;
	buildContext->build_ret = VmpBlockBuildContext::BUILD_CONTINUE;
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
		if (buildData->build_ret == VmpBlockBuildContext::BUILD_EXIT) {
			break;
		}
		else if (buildData->build_ret == VmpBlockBuildContext::BUILD_CONTINUE) {
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
			buildContext->build_ret = VmpBlockBuildContext::BUILD_MERGE;
		}
		break;
	}
    case VmpBlockBuildContext::FINISH_VM_INIT:
		Execute_FINISH_VM_INIT(nodeInput, fd);
		break;
	}
	return;
}