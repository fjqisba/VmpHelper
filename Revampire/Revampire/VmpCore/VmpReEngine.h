#pragma once
#include "../GhidraExtension/VmpFunction.h"
#include <math.h>

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
	void Decompile(size_t startAddr);
	VmpArchitecture* Arch();
private:
	VmpFunction* makeFunction(size_t startAddr);
	void clearFunction(size_t startAddr);
public:
private:
	VmpArchitecture* arch = nullptr;
	std::list<std::unique_ptr<VmpFunction>> funcCache;
};