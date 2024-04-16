#include "VmpControlFlow.h"
#include <sstream>
#include <fstream>
#include <graph.hpp>
#include "../Helper/IDAWrapper.h"
#include "../Manager/exceptions.h"
#include "../GhidraExtension/VmpFunction.h"
#include "../GhidraExtension/VmpArch.h"
#include "../Helper/UnicornHelper.h"
#include "../VmpCore/VmpReEngine.h"
#include "../VmpCore/VmpBlockBuilder.h"

VmpControlFlow::VmpControlFlow() :graph(this)
{

}

VmpControlFlow::~VmpControlFlow()
{

}

VmpControlFlowBuilder::VmpControlFlowBuilder(VmpFunction& fd):data(fd)
{

}

VmpControlFlowBuilder::~VmpControlFlowBuilder()
{

}

VmpFlowBuildContext::VmpFlowBuildContext()
{

}

void VmpRegStatus::ClearStatus()
{
	isSelected = false;
	reg_code = "";
	reg_stack = "";
}

std::string VmpBasicBlock::MakeGraphTxt()
{
	std::stringstream ss;
	for (unsigned int n = 0; n < insList.size(); ++n) {
		insList[n]->PrintRaw(ss);
	}
	return ss.str();
}

void VmpControlFlowShowGraph::refresh_graph(mutable_graph_t* g)
{
	g->resize(cfg->blocksMap.size());
	nodesList.resize(cfg->blocksMap.size());
	int nodeIdx = 0x0;
	for (auto& eBasicBlock : cfg->blocksMap) {
		VmpBasicBlock* tmpBlock = &eBasicBlock.second;
		tmpBlock->SetGraphIndex(nodeIdx);
		nodesList[nodeIdx++] = tmpBlock;
	}
	for (const auto& eTmpBlock : nodesList) {
		for (const auto& outBlock : eTmpBlock->outBlocks) {
			g->add_edge(eTmpBlock->GetGraphIndex(), outBlock->GetGraphIndex(), NULL);
		}
	}
}

void VmpControlFlowShowGraph::gen_graph_text(mutable_graph_t* g)
{
	txtList.resize(nodesList.size());
	for (unsigned int n = 0; n < nodesList.size(); ++n) {
		txtList[n] = nodesList[n]->MakeGraphTxt();
	}
}

ptrdiff_t __stdcall VmpControlFlowShowGraph::graph_callback(void* ud, int code, va_list va)
{
	VmpControlFlowShowGraph* showGraph = (VmpControlFlowShowGraph*)ud;
	switch (code)
	{
	case grcode_user_refresh:
	{
		mutable_graph_t* g = va_arg(va, mutable_graph_t*);
		showGraph->refresh_graph(g);
		return true;
	}
	case grcode_user_gentext:
	{
		mutable_graph_t* g = va_arg(va, mutable_graph_t*);
		showGraph->gen_graph_text(g);
		return true;
	}
	case grcode_user_text:
	{
		mutable_graph_t* g = va_arg(va, mutable_graph_t*);
		int node = va_arg(va, int);
		const char** text = va_arg(va, const char**);
		bgcolor_t* bgcolor = va_arg(va, bgcolor_t*);
		*text = showGraph->txtList[node].c_str();
		if (bgcolor != NULL) {
			*bgcolor = DEFCOLOR;
		}
		qnotused(g);
		return true;
	}
	break;
	default:
		break;
	}
	return 0x0;
}

void VmpControlFlowBuilder::linkBlockEdge(VmAddress from, VmAddress to)
{
	fromEdges[from].insert(to);
}

VmpBasicBlock* VmpControlFlowBuilder::createNewBlock(VmAddress startAddr, bool isVmBlock)
{
	VmpBasicBlock* newBlock = &data.cfg.blocksMap[startAddr];
	if (data.cfg.blocksMap.size() == 1) {
		data.cfg.startBlock = newBlock;
		newBlock->setStartBlock();
	}
	newBlock->blockEntry = startAddr;
	if (isVmBlock) {
		newBlock->setVmInsBlock();
	}
	return newBlock;
}



//是否是正常的终结指令

bool isNormalTerminalInstruction(RawInstruction* data)
{
	if (data == nullptr) {
		return true;
	}
	if (data->raw->id == X86_INS_RET) {
		return true;
	}
	if (data->raw->id == X86_INS_JMP) {
		//jmp eax
		if (data->raw->detail->x86.operands[0].type == X86_OP_REG) {
			return true;
		}
		//jmp [eax]
		else if (data->raw->detail->x86.operands[0].type == X86_OP_MEM) {
			return true;
		}
	}
	return false;
}

void VmpControlFlowBuilder::fallthruNormal(VmpFlowBuildContext& task)
{
	if (visited.count(task.start_addr)) {
		return;
	}
	visited.insert(task.start_addr);

	size_t curAddr = task.start_addr.raw;
	VmpBasicBlock* curBasicBlock = nullptr;
	while (true) {
		if (IDAWrapper::isVmpEntry(curAddr)) {
			if (curBasicBlock != nullptr) {
				RawInstruction* rawIns = static_cast<RawInstruction*>(curBasicBlock->insList.back().get());
				linkBlockEdge(rawIns->raw->address,curAddr);
			}
			addVmpEntryBuildTask(curAddr);
			return;
		}
		if (curBasicBlock == nullptr) {
			curBasicBlock = createNewBlock(curAddr, false);
			if (curBasicBlock == nullptr) {
				throw Exception("createNewBlock error");
			}
		}
		auto asmData = DisasmManager::Main().DecodeInstruction(curAddr);
		if (asmData == nullptr) {
			throw DisasmException("DecodeInstruction error");
		}
		RawInstruction* curIns = asmData.get();
		curBasicBlock->insList.push_back(std::move(asmData));
		if (isNormalTerminalInstruction(curIns)) {
			break;
		}
		else if (DisasmManager::IsBranchInstruction(curIns->raw)) {
			//To do...
		}
		else {
			curAddr = curAddr + curIns->raw->size;
		}
	}
}

void VmpControlFlowBuilder::addVmpEntryBuildTask(VmAddress startAddr)
{
	auto newTask = std::make_unique<VmpFlowBuildContext>();
	newTask->btype = VmpFlowBuildContext::HANDLE_VMP_ENTRY;
	newTask->start_addr = startAddr;
	anaQueue.push(std::move(newTask));
}

void VmpControlFlowBuilder::addNormalBuildTask(VmAddress startAddr)
{
	auto newTask = std::make_unique<VmpFlowBuildContext>();
	newTask->btype = VmpFlowBuildContext::HANDLE_NORMAL;
	newTask->start_addr = startAddr;
	anaQueue.push(std::move(newTask));
}

void VmpControlFlowBuilder::fallthruVmp(VmpFlowBuildContext& task)
{
	VmpBlockBuilder builder(*this);
	builder.BuildVmpBlock(&task);
	return;
}

VmpArchitecture* VmpControlFlowBuilder::Arch()
{
	return data.Arch();
}

bool VmpControlFlowBuilder::BuildCFG(size_t startAddr)
{
	auto startTask = std::make_unique<VmpFlowBuildContext>();
	startTask->btype = VmpFlowBuildContext::HANDLE_NORMAL;
	startTask->start_addr = startAddr;
	anaQueue.push(std::move(startTask));
	while (!anaQueue.empty()) {
		auto curTask = std::move(anaQueue.front());
		anaQueue.pop();
		if (curTask->btype == VmpFlowBuildContext::HANDLE_NORMAL) {
			fallthruNormal(*curTask);
		}
		else {
			fallthruVmp(*curTask);
		}
	}
	buildEdges();
	buildJmps();
	return true;
}

//是否会与下一条指令产生链接
bool IsConnectedInstruction(cs_insn* ins)
{
	if (ins->id == X86_INS_JMP) {
		return true;
	}
	if (ins->id >= X86_INS_JAE && ins->id <= X86_INS_JS) {
		return true;
	}
	return false;
}

void VmpControlFlowBuilder::buildJmps()
{
	for (auto& eBlock : data.cfg.blocksMap) {
		VmpBasicBlock* basicBlock = &eBlock.second;
		if (basicBlock->isEndBlock()) {
			continue;
		}
		vm_inst* endIns = basicBlock->insList.back().get();
		if (basicBlock->isVmInsBlock()) {
			VmpInstruction* vmIns = (VmpInstruction*)(endIns);
			if (vmIns->opType == VM_JMP) {
				VmpOpJmp* vOpJmp = (VmpOpJmp*)vmIns;
				vOpJmp->isBuildJmp = true;
				for (const auto& eOutBlock : basicBlock->outBlocks) {
					vOpJmp->branchList.push_back(eOutBlock->blockEntry.vmdata);
				}
			}
			else if (vmIns->opType == VM_EXIT) {
				VmpOpExit* vOpExit = (VmpOpExit*)vmIns;
				if (basicBlock->outBlocks.size() != 0) {
					vOpExit->exitAddress = basicBlock->outBlocks[0]->blockEntry.raw;
				}
			}
		}
		else {
			RawInstruction* rawIns = (RawInstruction*)(endIns);
			if (!IsConnectedInstruction(rawIns->raw)) {
				std::unique_ptr<UserOpConnect> vOpConnect = std::make_unique<UserOpConnect>();
				vOpConnect->addr = endIns->GetAddress();
				vOpConnect->connectAddr = basicBlock->outBlocks[0]->blockEntry.raw;
				basicBlock->insList.push_back(std::move(vOpConnect));
			}
		}
	}
}

void VmpControlFlowBuilder::buildEdges()
{
	for (auto& eBlock : data.cfg.blocksMap) {
		VmpBasicBlock* basicBlock = &eBlock.second;
		vm_inst* endIns = basicBlock->insList.back().get();
		VmAddress fromAddr = endIns->GetAddress();
		auto itEdge = fromEdges.find(fromAddr);
		if (itEdge == fromEdges.end()) {
			basicBlock->setEndBlock();
			continue;
		}
		auto edgeList = itEdge->second;
		std::set<VmAddress> linkedCache;
		for (const auto& edgeAddr : edgeList) {
			auto itChild = data.cfg.blocksMap.find(edgeAddr);
			if (itChild == data.cfg.blocksMap.end()) {
				continue;
			}
			if (linkedCache.count(edgeAddr)) {
				continue;
			}
			linkedCache.insert(edgeAddr);
			VmpBasicBlock* edgeBlock = &itChild->second;
			basicBlock->outBlocks.push_back(edgeBlock);
			edgeBlock->inBlocks.push_back(basicBlock);
		}
	}
}