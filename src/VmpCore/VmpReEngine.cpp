#include "VmpReEngine.h"
#include <nalt.hpp>
#include <graph.hpp>
#include "../GhidraExtension/VmpArch.h"
#include "../GhidraExtension/VmpFunction.h"
#include "../Helper/IDAWrapper.h"
#include "../Manager/exceptions.h"
#include "../Common/StringUtils.h"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

VmpReEngine::VmpReEngine()
{
	arch = new (std::nothrow)VmpArchitecture();
	if (arch == nullptr) {
		throw Exception("VmpReEngine::VmpReEngine(): Not enough memory.");
	}
	if (!handlerFactory.LoadHandlerPattern()) {
		throw Exception("VmpReEngine::VmpReEngine(): LoadHandlerPattern failed.");
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

Vmp3xHandlerFactory& VmpReEngine::HandlerCache()
{
	return handlerFactory;
}

Vmp3xHandlerFactory::Vmp3xHandlerFactory()
{
	initWorkingDirectory();
}

Vmp3xHandlerFactory::~Vmp3xHandlerFactory()
{
	SaveHandlerPattern();
}

void Vmp3xHandlerFactory::initWorkingDirectory()
{
	workingDir = IDAWrapper::idadir("plugins") + "\\Revampire";
	CreateDirectoryA(workingDir.c_str(), 0x0);
}

void Vmp3xHandlerFactory::SaveHandlerPattern()
{
	std::string md5 = IDAWrapper::get_input_file_md5();
	std::ofstream file(workingDir + "\\" + md5 + ".vmrule", std::ios::binary);
	if (!file.is_open()) {
		return;
	}
	cereal::BinaryOutputArchive archive(file);
	archive(handlerPatternMap);
	file.close();
}

bool Vmp3xHandlerFactory::LoadHandlerPattern()
{
	std::string md5 = IDAWrapper::get_input_file_md5();
	std::ifstream os(workingDir + "\\" + md5 + ".vmrule", std::ios::binary);
	if (!os.is_open()) {
		return true;
	}
	cereal::BinaryInputArchive archive(os);
	archive(handlerPatternMap);
	os.close();
	return true;
}

void VmpReEngine::MarkVmpEntry(size_t startAddr)
{
	IDAWrapper::set_cmt(startAddr, "vmp entry", false);
	clearAllFunction();
}

void VmpReEngine::Decompile(size_t startAddr)
{
	auto it = std::find_if(funcCache.begin(), funcCache.end(),
		[startAddr](const std::unique_ptr<VmpFunction>& func) {
			return func->startAddr == startAddr;
	});
	if (it == funcCache.end()) {
		return;
	}
	ghidra::Funcdata* fd = arch->AnaVmpFunction(it->get());
	if (!fd) {
		return;
	}
	std::stringstream ss;
	arch->print->setOutputStream(&ss);
	arch->print->docFunction(fd);
	std::string srcResult = ss.str();
	msg_clear();
	msg("%s\n", srcResult.c_str());
}

void VmpReEngine::Decompile_IDA(size_t startAddr)
{
	auto it = std::find_if(funcCache.begin(), funcCache.end(),
		[startAddr](const std::unique_ptr<VmpFunction>& func) {
			return func->startAddr == startAddr;
		});
	if (it == funcCache.end()) {
		return;
	}
	//VmpFunction* fd = it->get();
}

void VmpReEngine::clearAllFunction()
{
	for (auto it = funcCache.begin(); it != funcCache.end(); ++it) {
		qstring graphTitle;
		graphTitle.sprnt("vmp_%a", it->get()->startAddr);
		TWidget* widget = find_widget(graphTitle.c_str());
		if (widget) {
			close_widget(widget, 0x0);
		}
	}
	funcCache.clear();
}

void VmpReEngine::clearFunction(size_t startAddr)
{
	auto it = std::find_if(funcCache.begin(), funcCache.end(),
		[startAddr](const std::unique_ptr<VmpFunction>& func) {
			return func->startAddr == startAddr;
	});
	if (it != funcCache.end()) {
		qstring graphTitle;
		graphTitle.sprnt("vmp_%a", it->get()->startAddr);
		TWidget* widget = find_widget(graphTitle.c_str());
		if (widget) {
			close_widget(widget, 0x0);
		}
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
		fd->cfg.MergeNodes();
		fd->CreateGraph();
		handlerFactory.SaveHandlerPattern();
	}
	catch (Exception& e) {
		std::string what = e.what();
		clearFunction(startAddr);
	}
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif