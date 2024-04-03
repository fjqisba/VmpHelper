#pragma once
#include "../GhidraExtension/VmpFunction.h"

class VmpArchitecture;

class VmpReEngine
{
public:
	VmpReEngine();
	~VmpReEngine();
	static VmpReEngine& Instance();
public:
	void PrintGraph(size_t startAddr);
	void MarkVmpEntry(size_t startAddr);
private:
	VmpFunction* makeFunction(size_t startAddr);
private:
	VmpArchitecture* arch = nullptr;
	std::list<std::unique_ptr<VmpFunction>> funcCache;
};