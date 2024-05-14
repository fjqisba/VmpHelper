#pragma once
#include "../GhidraExtension/VmpFunction.h"
#include <cereal/cereal.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/archives/binary.hpp>
#include <math.h>

class VmpArchitecture;

class Vmp3xHandlerFactory
{
public:
	struct VmpHandlerRange
	{
		size_t startAddr;
		size_t endAddr;
		VmpHandlerRange() {
			startAddr = 0x0;
			endAddr = 0x0;
		}
		VmpHandlerRange(size_t from, size_t to) {
			startAddr = from;
			endAddr = to;
		}
		bool operator<(const VmpHandlerRange& other) const
		{
			return std::tie(startAddr, endAddr) < std::tie(other.startAddr, other.endAddr);
		}
		template <class Archive>
		void serialize(Archive& ar)
		{
			ar(startAddr, endAddr);
		}
	};
public:
	Vmp3xHandlerFactory();
	~Vmp3xHandlerFactory();
	bool LoadHandlerPattern();
	void SaveHandlerPattern();
private:
	void initWorkingDirectory();
public:
	std::map<VmpHandlerRange, std::unique_ptr<VmpInstruction>> handlerPatternMap;
private:
	std::string workingDir;
};

class VmpReEngine
{
public:
	VmpReEngine();
	~VmpReEngine();
	static VmpReEngine& Instance();
public:
	void PrintGraph(size_t startAddr);
	void MarkVmpEntry(size_t startAddr);
	void Decompile(size_t startAddr);
	VmpArchitecture* Arch();
	Vmp3xHandlerFactory& HandlerCache();
private:
	VmpFunction* makeFunction(size_t startAddr);
	void clearFunction(size_t startAddr);
	void clearAllFunction();
private:
	VmpArchitecture* arch = nullptr;
	Vmp3xHandlerFactory handlerFactory;
	std::list<std::unique_ptr<VmpFunction>> funcCache;
};