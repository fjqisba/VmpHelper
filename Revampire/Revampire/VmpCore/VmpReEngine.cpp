#include "VmpReEngine.h"
#include <nalt.hpp>
#include <graph.hpp>
#include "../GhidraExtension/VmpArch.h"
#include "../GhidraExtension/VmpFunction.h"
#include "../Helper/IDAWrapper.h"
#include "../Manager/exceptions.h"

VmpReEngine::VmpReEngine()
{
	arch = new (std::nothrow)VmpArchitecture();
	if (arch == nullptr) {
		throw Exception("VmpReEngine::VmpReEngine(): Not enough memory.");
	}

}

VmpReEngine::~VmpReEngine()
{
	if (arch) {
		delete arch;
	}
}

VmpReEngine& VmpReEngine::Instance()
{
	static VmpReEngine globalReEngine;
	return globalReEngine;
}

VmpArchitecture* VmpReEngine::Arch()
{
	return arch;
}

void VmpReEngine::MarkVmpEntry(size_t startAddr)
{
	IDAWrapper::set_cmt(startAddr, "vmp entry", false);
	func_t* anyFunc = get_func(startAddr);
	if (anyFunc) {
		clearFunction(anyFunc->start_ea);
	}
}

void VmpReEngine::clearFunction(size_t startAddr)
{
	auto it = std::find_if(funcCache.begin(), funcCache.end(),
		[startAddr](const std::unique_ptr<VmpFunction>& func) {
			return func->startAddr == startAddr;
	});
	if (it != funcCache.end()) {
		funcCache.erase(it);
	}
}

VmpFunction* VmpReEngine::makeFunction(size_t startAddr)
{
	//≤È’“ª∫¥ÊœÓ
	auto it = std::find_if(funcCache.begin(), funcCache.end(),
		[startAddr](const std::unique_ptr<VmpFunction>& func) {
			return func->startAddr == startAddr;
	});
	if (it != funcCache.end()) {
		return it->get();
	}
	//≥¢ ‘…æ≥˝ª∫¥Ê
	if (funcCache.size() >= 10) {
		for (auto it = funcCache.begin(); it != funcCache.end(); ++it) {
			qstring graphTitle;
			graphTitle.sprnt("vmp_%a", it->get()->startAddr);
			TWidget* widget = find_widget(graphTitle.c_str());
			if (widget) {
				continue;
			}
			funcCache.erase(it);
			break;
		}
	}
	std::unique_ptr<VmpFunction> retVmp = std::make_unique<VmpFunction>(arch, this);
	VmpFunction* retFunc = retVmp.get();
	funcCache.push_back(std::move(retVmp));
	return retFunc;
}

void VmpReEngine::PrintGraph(size_t startAddr)
{
	try {
		VmpFunction* fd = makeFunction(startAddr);
		fd->FollowVmp(startAddr);
		fd->CreateGraph();
	}
	catch (...) {
		clearFunction(startAddr);
	}
}