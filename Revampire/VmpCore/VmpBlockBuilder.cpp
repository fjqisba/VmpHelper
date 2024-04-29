#include "VmpBlockBuilder.h"
#include "../Ghidra/funcdata.hh"
#include "../GhidraExtension/VmpControlFlow.h"
#include "../GhidraExtension/VmpArch.h"
#include "../Helper/GhidraHelper.h"
#include "../Helper/IDAWrapper.h"
#include "../Helper/AsmBuilder.h"
#include "../Helper/VmpBlockAnalyzer.h"
#include "../Manager/exceptions.h"
#include <sstream>

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

int VmpBlockBuilder::vmRegStartAddr = 0x0;

size_t GetMemAccessSize(size_t addr)
{
	auto asmData = DisasmManager::Main().DecodeInstruction(addr);
	cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
	if (op1.type == X86_OP_MEM) {
		return op1.size;
	}
	return 0x0;
}

std::vector<ghidra::VarnodeData> ExtractVmStoreContext(ghidra::Funcdata* fd)
{
	std::vector<ghidra::VarnodeData> retContext;
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
		return retContext;
	}
	//将map转换为vector
	int startEsp = -4;
	for (unsigned int n = 0; n < 11; ++n) {
		auto it = storeContextMap.find(startEsp);
		if (it == storeContextMap.end()) {
			return retContext;
		}
		else {
			retContext.push_back(it->second);
		}
		startEsp = startEsp - 4;
	}
	return retContext;
}

void VmpBlockWalker::StartWalk(VmpUnicornContext& startCtx, size_t walkSize)
{
	unicorn.StartVmpTrace(startCtx, walkSize);
}

const std::vector<reg_context>& VmpBlockWalker::GetTraceList()
{
	return unicorn.traceList;
}

bool VmpBlockWalker::IsWalkToEnd()
{
	return idx >= unicorn.traceList.size();
}

void VmpBlockWalker::MoveToNext()
{
	idx = idx + curNodeSize;
	curNodeSize = 0x0;
}

size_t VmpBlockWalker::CurrentIndex()
{
	return idx;
}

VmpNode VmpBlockWalker::GetNextNode()
{
	VmpNode retNode;
	size_t curAddr = unicorn.traceList[idx].EIP;
	retNode.addrList = tfg.nodeMap[curAddr].addrList;
	for (unsigned int n = 0; n < retNode.addrList.size(); ++n) {
		retNode.contextList.push_back(unicorn.traceList[idx + n]);
	}
	curNodeSize = retNode.addrList.size();
	return retNode;
}

VmpBlockBuilder::VmpBlockBuilder(VmpControlFlowBuilder& cfg) :flow(cfg), walker(cfg.tfg)
{
	curBlock = nullptr;
	buildCtx = nullptr;
}

size_t tryGetVmCallExitAddress(ghidra::Funcdata* fd,int callOffset)
{
	ghidra::BlockBasic* bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	if (!bb) {
		return 0x0;
	}
	//倒叙遍历基本块
	auto itEnd = bb->endOp();
	while (itEnd != bb->beginOp()) {
		--itEnd;
		ghidra::PcodeOp* curOp = *itEnd;
		ghidra::Varnode* vOut = curOp->getOut();
		if (!vOut) {
			continue;
		}
		if (vOut->getSpace()->getName() != "stack") {
			continue;
		}
		int stackOff = vOut->getAddr().getOffset();
		if (stackOff != callOffset) {
			continue;
		}
		if (curOp->code() == ghidra::CPUI_COPY) {
			if (curOp->getIn(0)->isConstant()) {
				return curOp->getIn(0)->getOffset();
			}
		}
		//To do...
		return 0x0;
	}
	return 0x0;
}

bool VmpBlockBuilder::tryMatch_vPushReg(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 1 || loadCount < 3) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp = *itStore;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(2));
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
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
		else if (srcResult[n].name == buildCtx->vmreg.reg_code && srcResult[n].bAccessMem) {
			bContainVmCode = true;
		}
	}
	if (!bContainEsp || !bContainVmCode) {
		return false;
	}
	std::unique_ptr<VmpOpPushReg> vPushRegOp = std::make_unique<VmpOpPushReg>();
	vPushRegOp->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	vPushRegOp->opSize = GetMemAccessSize(loadEspAddr);
	for (unsigned int n = 0; n < nodeInput.contextList.size(); ++n) {
		reg_context& tmpContext = nodeInput.contextList[n];
		if (tmpContext.EIP == loadEspAddr) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			cs_x86_op& op1 = asmData->raw->detail->x86.operands[1];
			if (op1.type == X86_OP_MEM) {
				vPushRegOp->vmRegOffset = tmpContext.ReadMemReg(op1);
				executeVmpOp(nodeInput,std::move(vPushRegOp));
				return true;
			}
		}
	}
	return false;
}


bool VmpBlockBuilder::tryMatch_vPushImm(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 1 || loadCount < 2) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp = *itStore;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(2));
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
		return false;
	}
	const std::string& vmStackReg = dstResult[0].name;
	if (buildCtx->vmreg.reg_stack != vmStackReg) {
		return false;
	}
	bool bOnlyFromVmCode = true;
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (srcResult[n].bAccessMem) {
			if (srcResult[n].name != buildCtx->vmreg.reg_code) {
				bOnlyFromVmCode = false;
				break;
			}
		}
	}
	if (!bOnlyFromVmCode) {
		return false;
	}
	ghidra::PcodeOp* loadOp = *itLoad;
	std::unique_ptr<VmpOpPushImm> vPushImm = std::make_unique<VmpOpPushImm>();
	vPushImm->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	vPushImm->opSize = GetMemAccessSize(loadOp->getAddr().getOffset());
	for (unsigned int n = 0; n < nodeInput.contextList.size(); ++n) {
		reg_context& tmpContext = nodeInput.contextList[n];
		if (tmpContext.EIP == storeOp->getAddr().getOffset()) {
			auto tmpIns = DisasmManager::Main().DecodeInstruction(storeOp->getAddr().getOffset());
			cs_x86_op& op0 = tmpIns->raw->detail->x86.operands[0];
			cs_x86_op& op1 = tmpIns->raw->detail->x86.operands[1];
			if (op0.type == X86_OP_MEM && op1.type == X86_OP_REG) {
				vPushImm->immVal = tmpContext.ReadReg(op1.reg);
				executeVmpOp(nodeInput,std::move(vPushImm));
				return true;
			}
		}
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vJmpConst(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 0 || !loadCount) {
		return false;
	}
	auto itLoad = fd->obank.loadlist.begin();
	if (loadCount != 0x1) {
		return false;
	}
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	for (unsigned int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vn = retOp->getIn(n);
		std::string retRegName = fd->getArch()->translate->getRegisterName(vn->getSpace(), vn->getOffset(), vn->getSize());
		if (retRegName != "EIP") {
			continue;
		}
		GhidraHelper::PcodeOpTracer opTracer(fd);
		auto eipResult = opTracer.TraceInput(retOp->getAddr().getOffset(), vn);
		if (eipResult.size() != 2) {
			return false;
		}
		if (eipResult[0].bAccessMem ^ eipResult[1].bAccessMem) {
			//寄存器还尚未得知
			if (!buildCtx->vmreg.isSelected) {
				return true;
			}
			std::unique_ptr<VmpOpJmpConst> vOpJmpConst = std::make_unique<VmpOpJmpConst>();
			vOpJmpConst->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
			executeVmpOp(nodeInput, std::move(vOpJmpConst));
			return true;
		}
		return false;
	};
	return false;
}

bool VmpBlockBuilder::tryMatch_Mul(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 3 || loadCount != 3) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	ghidra::PcodeOp* storeOp1 = *itStore++;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp1->getAddr().getOffset(), storeOp1->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp1->getAddr().getOffset(), storeOp1->getIn(2));
	if (dstResult.size() != 1 || srcResult.size() != 2) {
		return false;
	}
	if (dstResult[0].name != buildCtx->vmreg.reg_stack) {
		return false;
	}
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (srcResult[n].name != buildCtx->vmreg.reg_stack) {
			return false;
		}
		if (!srcResult[n].bAccessMem) {
			return false;
		}
	}
	size_t mathOpAddr = storeOp1->getIn(2)->getDef()->getAddr().getOffset();
	auto asmData = DisasmManager::Main().DecodeInstruction(mathOpAddr);
	if(asmData->raw->id == X86_INS_IMUL) {
		std::unique_ptr<VmpOpImul> vOpImul = std::make_unique<VmpOpImul>();
		//To do... opsize fix
		vOpImul->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		executeVmpOp(nodeInput, std::move(vOpImul));
		return true;
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vJmp(ghidra::Funcdata* fd, VmpNode& nodeInput)
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
		if (loadRegName != buildCtx->vmreg.reg_stack) {
			return false;
		}
		std::unique_ptr<VmpOpJmp> vJmpOp = std::make_unique<VmpOpJmp>();
		vJmpOp->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		executeVmpOp(nodeInput, std::move(vJmpOp));
		return true;
	}
	else if (loadCount == 0x2) {
		ghidra::PcodeOp* loadOp1 = *itLoad++;
		ghidra::PcodeOp* loadOp2 = *itLoad++;
		ghidra::Varnode* vLoadReg = loadOp1->getIn(1);
		std::string loadRegName = fd->getArch()->translate->getRegisterName(vLoadReg->getSpace(), vLoadReg->getOffset(), vLoadReg->getSize());
		if (loadRegName != buildCtx->vmreg.reg_stack) {
			return false;
		}
		GhidraHelper::PcodeOpTracer opTracer(fd);
		auto srcResult = opTracer.TraceInput(loadOp2->getAddr().getOffset(), loadOp2->getIn(1));
		if (srcResult.size() != 1) {
			return false;
		}
		if (!srcResult[0].bAccessMem || srcResult[0].name != buildCtx->vmreg.reg_stack) {
			return false;
		}
		std::unique_ptr<VmpOpJmp> vJmpOp = std::make_unique<VmpOpJmp>();
		vJmpOp->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		executeVmpOp(nodeInput, std::move(vJmpOp));
		return true;
	}
	return false;
}

bool FastCheckVmpEntry(size_t startAddr)
{
	VmpTraceFlowGraph tfg;
	VmpBlockWalker walker(tfg);
	auto ctx = VmpUnicornContext::DefaultContext();
	ctx->context.EIP = startAddr;
	walker.StartWalk(*ctx, 0x1000);
	tfg.AddTraceFlow(walker.GetTraceList());
	tfg.MergeAllNodes();
	if (walker.IsWalkToEnd()) {
		return false;
	}
	VmpNode nodeInput = walker.GetNextNode();
	if (!nodeInput.addrList.size()) {
		return false;
	}
	ghidra::Funcdata* fd = gArch->AnaVmpHandler(&nodeInput);
	if (fd == nullptr) {
		throw GhidraException("ana vmp handler error");
	}
	auto storeContext = ExtractVmStoreContext(fd);
	if (storeContext.size() != 11) {
		return false;
	}
	return true;
}

bool VmpBlockBuilder::executeVmInit(VmpNode& nodeInput, VmpOpInit* inst)
{
	int stackOffset = 0x0;
	for (const auto& storeData : inst->storeContext) {
		this->buildCtx->save_reg_context.contextMap[stackOffset] = storeData;
		stackOffset = stackOffset - 1;
	}
	VmpUnicorn unicornEngine;
	unicornEngine.StartVmpTrace(*buildCtx->ctx, walker.CurrentIndex() + nodeInput.addrList.size() + 1);
	auto nextContext = unicornEngine.CopyCurrentUnicornContext();
	auto newBuildTask = std::make_unique<VmpFlowBuildContext>();
	newBuildTask->ctx = std::move(nextContext);
	newBuildTask->btype = VmpFlowBuildContext::HANDLE_VMP_JMP;
	newBuildTask->from_addr = inst->addr;
	flow.anaQueue.push(std::move(newBuildTask));
	buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
	return true;
}

bool VmpBlockBuilder::executeVmExit(VmpNode& nodeInput, VmpInstruction* inst)
{
	ghidra::Funcdata* fd = flow.Arch()->AnaVmpBasicBlock(curBlock);
	fd = flow.Arch()->OptimizeBlock(fd);
	GhidraHelper::VmpBranchExtractor branchExt;
	std::vector<size_t> branchList = branchExt.ExtractVmAllBranch(fd);
	if (branchList.size() == 1) {
		size_t vmCallExit = tryGetVmCallExitAddress(fd, 0x20);
		if (vmCallExit && FastCheckVmpEntry(vmCallExit)) {
			std::unique_ptr<VmpOpExitCall> vOpExitCall = std::make_unique<VmpOpExitCall>();
			vOpExitCall->addr = inst->addr;
			vOpExitCall->callAddr = branchList[0];
			curBlock->insList.push_back(std::move(vOpExitCall));
			auto newBuildTask = std::make_unique<VmpFlowBuildContext>();
			newBuildTask->btype = VmpFlowBuildContext::HANDLE_VMP_ENTRY;
			newBuildTask->from_addr = inst->addr;
			newBuildTask->start_addr = vmCallExit;
			flow.anaQueue.push(std::move(newBuildTask));
			buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
			return true;
		}
		if (!IDAWrapper::isVmpEntry(branchList[0])) {
			flow.addNormalBuildTask(branchList[0]);
			flow.linkBlockEdge(inst->addr, branchList[0]);
			buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
			return true;
		}
	}
	buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
	return true;
}

bool VmpBlockBuilder::executeVmJmpConst(VmpNode& nodeInput, VmpOpJmpConst* inst)
{
	VmpUnicorn unicornEngine;
	//ghidra::Funcdata* fd = flow.Arch()->AnaVmpBasicBlock(curBlock);
	//updateSaveRegContext(fd);
	unicornEngine.StartVmpTrace(*buildCtx->ctx, walker.CurrentIndex() + nodeInput.addrList.size() + 1);
	auto nextContext = unicornEngine.CopyCurrentUnicornContext();
	auto newBuildTask = std::make_unique<VmpFlowBuildContext>();
	newBuildTask->ctx = std::move(nextContext);
	newBuildTask->btype = VmpFlowBuildContext::HANDLE_VMP_JMP;
	newBuildTask->from_addr = inst->addr;
	flow.anaQueue.push(std::move(newBuildTask));
	buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
	return true;
}

bool isSaveContextOffset(int stackOffset)
{
	if (stackOffset >= -44 && stackOffset <= -4) {
		return true;
	}
	stackOffset = stackOffset - VmpBlockBuilder::vmRegStartAddr;
	if (stackOffset < 0) {
		return false;
	}
	return true;
}

//每次在执行vJmp前都会往堆栈压入11个参数

void VmpBlockBuilder::updateSaveRegContext(ghidra::Funcdata* fd)
{
	//ghidra::BlockBasic* bb = (ghidra::BlockBasic*)fd->getBasicBlocks().getStartBlock();
	//if (!bb) {
	//	return;
	//}
	////遍历基本块
	//auto itEnd = bb->endOp();
	//for (auto itBegin = bb->beginOp(); itBegin != itEnd; itBegin++) {
	//	ghidra::PcodeOp* curOp = *itBegin;
	//	if (!curOp->isAssignment()) {
	//		continue;
	//	}
	//	ghidra::Varnode* vOut = curOp->getOut();
	//	if (!vOut) {
	//		continue;
	//	}
	//	if (vOut->getSpace()->getName() != "stack") {
	//		continue;
	//	}
	//	//位于存储堆栈之间
	//	int stackOffset = vOut->getAddr().getOffset();
	//	int offKey = 0x0;
	//	if (!isSaveContextOffset(stackOffset)) {
	//		continue;
	//	}
	//	int saveIdx = stackOffset / 4;
	//	if (stackOffset % 4) {
	//		buildCtx->save_reg_context.eraseSaveReg(saveIdx);
	//		continue;
	//	}
	//	if (curOp->code() == ghidra::CPUI_COPY) {
	//		ghidra::Varnode* vInput = curOp->getIn(0);
	//		if (vInput->isConstant()) {
	//			buildCtx->save_reg_context.eraseSaveReg(saveIdx);
	//			continue;
	//		}
	//		if (vInput->isInput()) {
	//			std::string regName = GhidraHelper::GetVarnodeRegName(vInput);
	//			if (!regName.empty()) {
	//				buildCtx->save_reg_context.updateSaveReg(saveIdx, regName);
	//				continue;
	//			}
	//		}
	//		if (vInput->getSpace()->getName() == "stack") {
	//			int inputOffset = vInput->getAddr().getOffset();
	//			if (!isSaveContextOffset(inputOffset)) {
	//				continue;
	//			}
	//			if (inputOffset % 4) {
	//				buildCtx->save_reg_context.eraseSaveReg(saveIdx);
	//				continue;
	//			}
	//			buildCtx->save_reg_context.copySaveReg(saveIdx, inputOffset / 4);
	//			continue;
	//		}
	//		//什么都没识别出来,直接干掉
	//		buildCtx->save_reg_context.eraseSaveReg(saveIdx);
	//	}
	//}
	return;
}

bool VmpBlockBuilder::executeVmJmp(VmpNode& nodeInput, VmpOpJmp* inst)
{
	VmpUnicorn unicornEngine;
	GhidraHelper::VmpBranchExtractor branchExt;
	ghidra::Funcdata* fd = flow.Arch()->AnaVmpBasicBlock(curBlock);
	fd = flow.Arch()->OptimizeBlock(fd);
	std::vector<size_t> branchList = branchExt.ExtractVmAllBranch(fd);
	if (branchList.size() == 1) {
		//size_t vmCall = tryGetVmCallExitAddress(fd, 0x28);
		//判断vJmp是不是vmCall
		//if (vmCall) {
			//To do...	
		//}
		unicornEngine.StartVmpTrace(*buildCtx->ctx, walker.CurrentIndex() + nodeInput.addrList.size() + 1);
		auto nextContext = unicornEngine.CopyCurrentUnicornContext();
		auto newBuildTask = std::make_unique<VmpFlowBuildContext>();
		newBuildTask->ctx = std::move(nextContext);
		newBuildTask->save_reg_context = buildCtx->save_reg_context;
		newBuildTask->btype = VmpFlowBuildContext::HANDLE_VMP_JMP;
		newBuildTask->from_addr = inst->addr;
		flow.anaQueue.push(std::move(newBuildTask));
		buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
		return true;
	}
	else if (branchList.size() == 2) {

		//先运行到执行vmJmp之前
		unicornEngine.StartVmpTrace(*buildCtx->ctx, walker.CurrentIndex() + 1);

		//拷贝出两份环境
		auto nextContext1 = unicornEngine.CopyCurrentUnicornContext();
		auto nextContext2 = unicornEngine.CopyCurrentUnicornContext();

		//模拟执行环境1
		nextContext1->ChangeVmJmpVal(buildCtx->vmreg.reg_stack, branchList[0]);
		unicornEngine.StartVmpTrace(*nextContext1, nodeInput.addrList.size() + 1);

		auto newTask1 = std::make_unique<VmpFlowBuildContext>();
		newTask1->ctx = unicornEngine.CopyCurrentUnicornContext();
		newTask1->save_reg_context = buildCtx->save_reg_context;
		newTask1->btype = VmpFlowBuildContext::HANDLE_VMP_JMP;
		newTask1->from_addr = inst->addr;
		flow.anaQueue.push(std::move(newTask1));

		//模拟执行环境2
		nextContext2->ChangeVmJmpVal(buildCtx->vmreg.reg_stack, branchList[1]);
		unicornEngine.StartVmpTrace(*nextContext2, nodeInput.addrList.size() + 1);

		auto newTask2 = std::make_unique<VmpFlowBuildContext>();
		newTask2->ctx = unicornEngine.CopyCurrentUnicornContext();
		newTask2->save_reg_context = buildCtx->save_reg_context;
		newTask2->btype = VmpFlowBuildContext::HANDLE_VMP_JMP;
		newTask2->from_addr = inst->addr;
		flow.anaQueue.push(std::move(newTask2));
		buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
		return true;
	}
	buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
	return true;
}

bool VmpBlockBuilder::executeVmpOp(VmpNode& nodeInput,std::unique_ptr<VmpInstruction> inst)
{
	VmpInstruction* vmInst = inst.get();
	if (vmInst->opType == VM_INIT) {
		buildCtx->status = VmpFlowBuildContext::FINISH_VM_INIT;
	}

	if (!curBlock) {
		//存在来源地址
		if (buildCtx->from_addr.raw) {
			flow.linkBlockEdge(buildCtx->from_addr, vmInst->addr);
		}
		if (flow.visited.count(vmInst->addr)) {
			buildCtx->status = VmpFlowBuildContext::FINISH_MATCH;
			return true;
		}
		flow.visited.insert(vmInst->addr);
		curBlock = flow.createNewBlock(vmInst->addr, true);
	}
	curBlock->insList.push_back(std::move(inst));

	if (vmInst->opType == VM_INIT) {
		executeVmInit(nodeInput, (VmpOpInit*)vmInst);
	}
	else if (vmInst->opType == VM_JMP) {
		executeVmJmp(nodeInput, (VmpOpJmp*)vmInst);
		buildCtx->vmreg.ClearStatus();
	}
	else if (vmInst->opType == VM_JMP_CONST) {
		executeVmJmpConst(nodeInput, (VmpOpJmpConst*)vmInst);
	}
	else if (vmInst->opType == VM_EXIT) {
		executeVmExit(nodeInput, vmInst);
	}
	return true;
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

bool VmpBlockBuilder::tryMatch_vMemAccess(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	//load vmStack,load vmStack, store vmStack,load vmCode
	if (storeCount != 1 || loadCount != 3) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp = *itStore;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(2));
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (srcResult.size() != 1) {
		return false;
	}
	if (srcResult[0].name != buildCtx->vmreg.reg_stack || !srcResult[0].bAccessMem) {
		return false;
	}
	if (dstResult[0].name != buildCtx->vmreg.reg_stack) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
		std::unique_ptr<VmpOpWriteMem> vOpWriteMem = std::make_unique<VmpOpWriteMem>();
		vOpWriteMem->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		//To do...fix opsize
		vOpWriteMem->opSize = 0x4;
		executeVmpOp(nodeInput, std::move(vOpWriteMem));
	}
	else {
		std::unique_ptr<VmpOpReadMem> vOpReadMem = std::make_unique<VmpOpReadMem>();
		vOpReadMem->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		vOpReadMem->opSize = GetMemAccessSize((*++itLoad)->getAddr().getOffset());
		executeVmpOp(nodeInput, std::move(vOpReadMem));
	}
	return true;
}

bool VmpBlockBuilder::tryMatch_vShrd(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 2 || loadCount != 4) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp1 = *itStore++;
	ghidra::PcodeOp* storeOp2 = *itStore++;
	ghidra::PcodeOp* loadOp1 = *itLoad++;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp1->getAddr().getOffset(), storeOp1->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp1->getAddr().getOffset(), storeOp1->getIn(2));
	//dstResult来源于vmStack
	if (dstResult.size() != 1 || dstResult[0].bAccessMem || dstResult[0].name != buildCtx->vmreg.reg_stack) {
		return false;
	}
	//src全部来源于stack
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (srcResult[n].bAccessMem) {
			if (srcResult[n].name == buildCtx->vmreg.reg_stack) {
				continue;
			}
			return false;
		}
	}
	auto asmData = DisasmManager::Main().DecodeInstruction(storeOp1->getIn(2)->getDef()->getAddr().getOffset());
	if (asmData->raw->id == X86_INS_SHRD) {
		std::unique_ptr<VmpOpShrd> vOpShrd = std::make_unique<VmpOpShrd>();
		vOpShrd->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		executeVmpOp(nodeInput, std::move(vOpShrd));
		return true;
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vLogicalOp(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	//条件,2次store,3次load
	//store vmStack,store vmStack
	//load vmCode,load vmCode
	if (storeCount != 2 || loadCount != 3) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	auto itLoad = fd->obank.loadlist.begin();
	ghidra::PcodeOp* storeOp1 = *itStore++;
	ghidra::PcodeOp* storeOp2 = *itStore++;
	ghidra::PcodeOp* loadOp1 = *itLoad++;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp1->getAddr().getOffset(), storeOp1->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp1->getAddr().getOffset(), storeOp1->getIn(2));
	//dstResult来源于vmStack
	if (dstResult.size() != 1) {
		return false;
	}
	if (dstResult[0].bAccessMem) {
		return false;
	}
	if (dstResult[0].name != buildCtx->vmreg.reg_stack) {
		return false;
	}
	//src全部来源于stack
	for (unsigned int n = 0; n < srcResult.size(); ++n) {
		if (srcResult[n].bAccessMem) {
			if (srcResult[n].name == buildCtx->vmreg.reg_stack) {
				continue;
			}
			return false;
		}
	}
	ghidra::OpCode logicCode = CheckLogicPattern(storeOp1->getIn(2)->getDef());
	if (logicCode == ghidra::CPUI_INT_ADD) {
		std::unique_ptr<VmpOpAdd> vAddOp = std::make_unique<VmpOpAdd>();
		vAddOp->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		vAddOp->opSize = GetMemAccessSize(loadOp1->getAddr().getOffset());
		executeVmpOp(nodeInput, std::move(vAddOp));
		return true;
	}
	if (logicCode == ghidra::CPUI_INT_AND) {
		std::unique_ptr<VmpOpNor> vOpNor = std::make_unique<VmpOpNor>();
		vOpNor->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		vOpNor->opSize = GetMemAccessSize(loadOp1->getAddr().getOffset());
		executeVmpOp(nodeInput, std::move(vOpNor));
		return true;
	}
	else if (logicCode == ghidra::CPUI_INT_OR) {
		std::unique_ptr<VmpOpNand> vOpNand = std::make_unique<VmpOpNand>();
		vOpNand->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		vOpNand->opSize = GetMemAccessSize(loadOp1->getAddr().getOffset());
		executeVmpOp(nodeInput, std::move(vOpNand));
		return true;
	}
	else if (logicCode == ghidra::CPUI_INT_RIGHT) {
		std::unique_ptr<VmpOpShr> vOpShr = std::make_unique<VmpOpShr>();
		vOpShr->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		vOpShr->opSize = GetMemAccessSize(loadOp1->getAddr().getOffset());
		executeVmpOp(nodeInput, std::move(vOpShr));
		return true;
	}
	else if (logicCode == ghidra::CPUI_INT_LEFT) {
		std::unique_ptr<VmpOpShl> vOpShl = std::make_unique<VmpOpShl>();
		vOpShl->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		vOpShl->opSize = GetMemAccessSize(loadOp1->getAddr().getOffset());
		executeVmpOp(nodeInput, std::move(vOpShl));
		return true;
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vJunkCode(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (!storeCount && !loadCount) {
		return true;
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vCheckEsp(ghidra::Funcdata* fd, VmpNode& nodeInput)
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
				//std::unique_ptr<VmpOpCheckEsp> vCheckEsp = std::make_unique<VmpOpCheckEsp>();
				//vCheckEsp->addr.raw = nodeInput.addrList[0];
				//vCheckEsp->addr.vmdata = nodeInput.contextList[0].ReadReg(buildCtx->vmreg.reg_code);
				//executeVmpOp(std::move(vCheckEsp));
				return true;
			}
		}
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vCpuid(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	if (storeCount < 4) {
		return false;
	}
	auto itStoreBegin = fd->obank.storelist.begin();
	auto itStoreEnd = fd->obank.storelist.end();
	while (itStoreBegin != itStoreEnd) {
		ghidra::PcodeOp* curStore = *itStoreBegin++;
		GhidraHelper::PcodeOpTracer opTracer(fd);
		auto srcResult = opTracer.TraceInput(curStore->getAddr().getOffset(), curStore->getIn(2));
		if (!srcResult.size()) {
			return false;
		}
		if (srcResult[0].name.find("cpuid") == -1) {
			return false;
		}
	}
	std::unique_ptr<VmpOpCpuid> vOpCpuid = std::make_unique<VmpOpCpuid>();
	vOpCpuid->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	executeVmpOp(nodeInput, std::move(vOpCpuid));
	return true;
}

bool VmpBlockBuilder::tryMatch_vPopReg(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 1 || loadCount != 3) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	ghidra::PcodeOp* opStore = *itStore;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(opStore->getAddr().getOffset(), opStore->getIn(1));
	auto srcResult = opTracer.TraceInput(opStore->getAddr().getOffset(), opStore->getIn(2));
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
	if (!buildCtx->vmreg.isSelected) {
		buildCtx->vmreg.reg_code = vmCodeTraceResult.name;
		buildCtx->vmreg.reg_stack = vmStackReg;
		buildCtx->vmreg.isSelected = true;
	}
	else {
		if (buildCtx->vmreg.reg_code != vmCodeTraceResult.name) {
			return false;
		}
		if (buildCtx->vmreg.reg_stack != vmStackReg) {
			return false;
		}
	}
	std::unique_ptr<VmpOpPopReg> vPopRegOp = std::make_unique<VmpOpPopReg>();
	vPopRegOp->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	vPopRegOp->opSize = GetMemAccessSize(srcResult[0].addr);
	for (unsigned int n = 0; n < nodeInput.contextList.size(); ++n) {
		reg_context& tmpContext = nodeInput.contextList[n];
		if (tmpContext.EIP == opStore->getAddr().getOffset()) {
			auto asmData = DisasmManager::Main().DecodeInstruction(tmpContext.EIP);
			if (asmData->raw->id == X86_INS_MOV || asmData->raw->id == X86_INS_MOVZX || asmData->raw->id == X86_INS_MOVSX) {
				cs_x86_op& op0 = asmData->raw->detail->x86.operands[0];
				vPopRegOp->vmRegOffset = tmpContext.ReadMemReg(op0);
				executeVmpOp(nodeInput, std::move(vPopRegOp));
				return true;
			}
		}
	}
	return false;
}

bool VmpBlockBuilder::Execute_FINISH_VM_INIT()
{
	if (walker.IsWalkToEnd()) {
		return false;
	}
	VmpNode nodeInput = walker.GetNextNode();
	if (!nodeInput.addrList.size()) {
		return false;
	}
	ghidra::Funcdata* fd = flow.Arch()->AnaVmpHandler(&nodeInput);
	if (fd == nullptr) {
		throw GhidraException("ana vmp handler error");
	}
	if (tryMatch_vPopReg(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vPushReg(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vPushImm(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vPushVsp(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vMemAccess(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vLogicalOp(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vShrd(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vCpuid(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_Mul(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vJmpConst(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vJmp(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vWriteVsp(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vExit(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vCheckEsp(fd, nodeInput)) {
		return true;
	}
	if (tryMatch_vJunkCode(fd, nodeInput)) {
		return true;
	}
	std::unique_ptr<VmpOpUnknown> vOpUnknown = std::make_unique<VmpOpUnknown>();
	vOpUnknown->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	executeVmpOp(nodeInput, std::move(vOpUnknown));
	return true;
}

bool VmpBlockBuilder::updateVmRegOffset(ghidra::Funcdata* fd)
{
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	for (int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vnReg = retOp->getIn(n);
		if (GhidraHelper::GetVarnodeRegName(vnReg) != "ESP") {
			continue;
		}
		ghidra::PcodeOp* defOp = vnReg->getDef();
		if (!defOp) {
			continue;
		}
		if (defOp->code() == ghidra::CPUI_COPY) {
			defOp = defOp->getIn(0)->getDef();
		}
		if (defOp->code() == ghidra::CPUI_PTRSUB) {
			if (defOp->getIn(0)->isInput() && GhidraHelper::GetVarnodeRegName(defOp->getIn(0)) == "ESP") {
				if (defOp->getIn(1)->isConstant()) {
					int offset = defOp->getIn(1)->getOffset();
					vmRegStartAddr = VmpUnicornContext::DefaultEsp() + offset;
					return true;
				}
			}
		}
	}
	return false;
}



bool VmpBlockBuilder::Execute_FIND_VM_INIT()
{
	if (walker.IsWalkToEnd()) {
		return false;
	}
	VmpNode nodeInput = walker.GetNextNode();
	if (!nodeInput.addrList.size()) {
		return false;
	}
	ghidra::Funcdata* fd = flow.Arch()->AnaVmpHandler(&nodeInput);
	if (fd == nullptr) {
		throw GhidraException("ana vmp handler error");
	}
	auto storeContext = ExtractVmStoreContext(fd);
	if (storeContext.size() != 11) {
		return false;
	}
	if (!updateVmRegOffset(fd)) {
		return false;
	}
	std::unique_ptr<VmpOpInit> opInitVm = std::make_unique<VmpOpInit>();
	opInitVm->storeContext = storeContext;
	opInitVm->addr = VmAddress(nodeInput.addrList[0], nodeInput.addrList[0]);
	executeVmpOp(nodeInput, std::move(opInitVm));
	walker.MoveToNext();
	return true;
}

bool VmpBlockBuilder::tryMatch_vWriteVsp(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 0 || loadCount != 2) {
		return false;
	}
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	for (unsigned int n = 0; n < retOp->numInput(); ++n) {
		std::string retReg = GhidraHelper::GetVarnodeRegName(retOp->getIn(n));
		if (retReg.empty()) {
			continue;
		}
		if (retReg != buildCtx->vmreg.reg_stack) {
			continue;
		}
		GhidraHelper::PcodeOpTracer opTracer(fd);
		auto inputReg = opTracer.TraceInput(retOp->getAddr().getOffset(), retOp->getIn(n));
		if (inputReg.size() != 1) {
			return false;
		}
		if (inputReg[0].name != buildCtx->vmreg.reg_stack) {
			return false;
		}
		if (!inputReg[0].bAccessMem) {
			return false;
		}
		std::unique_ptr<VmpOpWriteVSP> vOpWriteVSP = std::make_unique<VmpOpWriteVSP>();
		vOpWriteVSP->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
		executeVmpOp(nodeInput, std::move(vOpWriteVSP));
		return true;
	}
	return false;
}

bool VmpBlockBuilder::tryMatch_vPushVsp(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (storeCount != 1 || loadCount != 1) {
		return false;
	}
	auto itStore = fd->obank.storelist.begin();
	ghidra::PcodeOp* storeOp = *itStore++;
	GhidraHelper::PcodeOpTracer opTracer(fd);
	auto dstResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(1));
	auto srcResult = opTracer.TraceInput(storeOp->getAddr().getOffset(), storeOp->getIn(2));
	if (dstResult.size() != 1 || srcResult.size() != 1) {
		return false;
	}
	if (dstResult[0].name != buildCtx->vmreg.reg_stack || dstResult[0].bAccessMem) {
		return false;
	}
	if (srcResult[0].name != buildCtx->vmreg.reg_stack || srcResult[0].bAccessMem) {
		return false;
	}
	std::unique_ptr<VmpOpPushVSP> vOpPushVSP = std::make_unique<VmpOpPushVSP>();
	vOpPushVSP->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	executeVmpOp(nodeInput, std::move(vOpPushVSP));
	return true;
}

bool VmpBlockBuilder::tryMatch_vExit(ghidra::Funcdata* fd, VmpNode& nodeInput)
{
	size_t storeCount = fd->obank.storelist.size();
	size_t loadCount = fd->obank.loadlist.size();
	if (loadCount < 7) {
		return false;
	}
	std::map<int, ghidra::VarnodeData> exitContextMap;
	ghidra::PcodeOp* retOp = fd->getFirstReturnOp();
	for (int n = 0; n < retOp->numInput(); ++n) {
		ghidra::Varnode* vnReg = retOp->getIn(n);
		if (vnReg->getSpace()->getName() != "register") {
			continue;
		}
		ghidra::PcodeOp* defOp = vnReg->getDef();
		if (!defOp) {
			continue;
		}
		if (defOp->code() == ghidra::CPUI_LOAD) {
			if (!defOp->getIn(1)->isInput()) {
				defOp = defOp->getIn(1)->getDef();
			}
		}
		if (!defOp) {
			continue;
		}
		ghidra::VarnodeData tmpData;
		if (defOp->code() == ghidra::CPUI_LOAD) {
			tmpData.space = vnReg->getSpace();
			tmpData.offset = vnReg->getOffset();
			tmpData.size = vnReg->getSize();
			exitContextMap[0x0] = tmpData;
		}
		else if (defOp->code() == ghidra::CPUI_PTRADD) {
			if (defOp->getIn(2)->isConstant() && defOp->getIn(2)->getOffset() == 0x4) {
				if (defOp->getIn(1)->isConstant()) {
					tmpData.space = vnReg->getSpace();
					tmpData.offset = vnReg->getOffset();
					tmpData.size = vnReg->getSize();
					exitContextMap[defOp->getIn(1)->getOffset()] = tmpData;
				}
			}
		}
	}
	std::unique_ptr<VmpOpExit> vOpExit = std::make_unique<VmpOpExit>();
	vOpExit->addr = nodeInput.readVmAddress(buildCtx->vmreg.reg_code);
	int base = 0x0;
	for (unsigned int n = 0; n < 10; ++n) {
		auto it = exitContextMap.find(base);
		if (it == exitContextMap.end()) {
			return false;
		}
		else {
			vOpExit->exitContext.push_back(it->second);
		}
		base = base + 1;
	}
	executeVmpOp(nodeInput,std::move(vOpExit));
	return true;
}


bool VmpBlockBuilder::BuildVmpBlock(VmpFlowBuildContext* ctx)
{
	buildCtx = ctx;
	if (buildCtx->ctx == nullptr) {
		buildCtx->ctx = VmpUnicornContext::DefaultContext();
		buildCtx->ctx->context.EIP = buildCtx->start_addr.raw;
	}
	walker.StartWalk(*(buildCtx->ctx), 0x10000);
	flow.tfg.AddTraceFlow(walker.GetTraceList());
	flow.tfg.MergeAllNodes();

	std::stringstream ss;
	flow.tfg.DumpGraph(ss, true);
	std::string graphTxt = ss.str();

	if (buildCtx->btype == VmpFlowBuildContext::HANDLE_VMP_ENTRY) {
		buildCtx->status = VmpFlowBuildContext::FIND_VM_INIT;
	}
	else if (buildCtx->btype == VmpFlowBuildContext::HANDLE_VMP_JMP) {
		buildCtx->status = VmpFlowBuildContext::FINISH_VM_INIT;
	}

	while (true) {
		switch (buildCtx->status)
		{
		case VmpFlowBuildContext::FIND_VM_INIT:
			if (!Execute_FIND_VM_INIT()) {
				return false;
			}
			break;
		case VmpFlowBuildContext::FINISH_VM_INIT:
			if (!Execute_FINISH_VM_INIT()) {
				return false;
			}
			walker.MoveToNext();
			break;
		case VmpFlowBuildContext::FINISH_MATCH:
			return true;
		case VmpFlowBuildContext::MATCH_ERROR:
			return false;
		}
	}
	return true;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif

