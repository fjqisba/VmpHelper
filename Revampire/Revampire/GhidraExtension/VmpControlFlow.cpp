#include "VmpControlFlow.h"
#include <sstream>
#include <fstream>
#include <graph.hpp>
#include "../Helper/IDAWrapper.h"
#include "../Manager/exceptions.h"
#include "../GhidraExtension/VmpFunction.h"
#include "../GhidraExtension/VmpArch.h"
#include "../Helper/UnicornHelper.h"
#include "../VmpCore/VmpHandler.h"
#include "../VmpCore/VmpReEngine.h"

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

std::string VmpBasicBlock::MakeGraphTxt()
{
	std::stringstream ss;
	for (unsigned int n = 0; n < insList.size(); ++n) {
		if (insList[n]->IsRawInstruction()) {
			RawInstruction* ins = static_cast<RawInstruction*>(insList[n].get());
			cs_insn* raw = ins->raw;
			ss << "0x" << std::hex << raw->address << "\t" << raw->mnemonic << " " << raw->op_str << "\n";
		}
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

VmpBasicBlock* VmpControlFlowBuilder::createNewBlock(VmAddress startAddr)
{
	VmpBasicBlock* newBlock = &data.cfg.blocksMap[startAddr];
	if (data.cfg.blocksMap.size() == 1) {
		data.cfg.startBlock = newBlock;
	}
	return newBlock;
}

bool VmpControlFlowBuilder::isVmpEntry(size_t startAddr)
{
	if (IDAWrapper::get_cmt(startAddr) == "vmp entry") {
		return true;
	}
	return false;
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

void VmpControlFlowBuilder::fallthruNormal(AnaTask& task)
{
	size_t curAddr = task.vmAddr.raw;
	VmpBasicBlock* curBasicBlock = nullptr;
	while (true) {
		if (isVmpEntry(curAddr)) {
			if (curBasicBlock != nullptr) {
				RawInstruction* rawIns = static_cast<RawInstruction*>(curBasicBlock->insList.back().get());
				linkBlockEdge(rawIns->raw->address,curAddr);
			}
			auto newTask = std::make_unique<AnaTask>();
			newTask->type = HANDLE_VM_ENTRY;
			newTask->vmAddr = VmAddress(curAddr, 0x0);
			anaQueue.push(std::move(newTask));
			return;
		}
		if (curBasicBlock == nullptr) {
			curBasicBlock = createNewBlock(curAddr);
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


bool VmpControlFlowBuilder::fallthruVmp(AnaTask& task)
{
	VmpBlockWalker walker(tfg);
	if (task.ctx == nullptr) {
		task.ctx = VmpUnicornContext::DefaultContext();
		task.ctx->context.EIP = task.vmAddr.raw;
	}
	walker.StartWalk(*task.ctx, 0x10000);
	tfg.AddTraceFlow(walker.GetTraceList());
	tfg.MergeAllNodes();

	VmpBlockBuildContext buildContext;
	buildContext.bBlock = createNewBlock(task.vmAddr);
	if (task.vmAddr.vmdata == 0) {
		buildContext.status = VmpBlockBuildContext::FIND_VM_INIT;
	}
	else {
		buildContext.status = VmpBlockBuildContext::FINISH_VM_INIT;
	}
	VmpHandlerFactory handlerFactory(data.Arch());
	return handlerFactory.BuildVmpBlock(&buildContext, walker);
}

VmpArchitecture* VmpControlFlowBuilder::Architecture()
{
	return data.Arch();
}

bool VmpControlFlowBuilder::BuildCFG(size_t startAddr)
{
	auto startTask = std::make_unique<AnaTask>();
	startTask->type = FIND_VM_ENTRY;
	startTask->vmAddr = VmAddress(startAddr, 0x0);
	anaQueue.push(std::move(startTask));
	while (!anaQueue.empty()) {
		auto curTask = std::move(anaQueue.front());
		anaQueue.pop();
		if (visited.count(curTask->vmAddr)) {
			continue;
		}
		visited.insert(curTask->vmAddr);
		switch (curTask->type) {
		case FIND_VM_ENTRY:
			fallthruNormal(*curTask);
			break;
		case HANDLE_VM_ENTRY:
			fallthruVmp(*curTask);
			break;
		}
	}
	return true;
}