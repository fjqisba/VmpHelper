#pragma once
#include "VmpControlFlow.h"

class VmpArchitecture;

class VmpFunction
{
public:
	VmpFunction(VmpArchitecture* arch);
	~VmpFunction();
	void FollowVmp(size_t startAddr);
	void CreateGraph();
	VmpArchitecture* Arch();
public:
	size_t startAddr;
	VmpControlFlow cfg;
private:
	VmpArchitecture* arch;
};