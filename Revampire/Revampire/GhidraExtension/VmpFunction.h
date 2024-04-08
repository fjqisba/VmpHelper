#pragma once
#include "VmpControlFlow.h"

class VmpArchitecture;
class VmpReEngine;

class VmpFunction
{
public:
	VmpFunction(VmpArchitecture* arch, VmpReEngine* re);
	~VmpFunction();
	void FollowVmp(size_t startAddr);
	void CreateGraph();
	VmpArchitecture* Arch();
	VmpReEngine* VmpEngine();
public:
	size_t startAddr;
	VmpControlFlow cfg;
private:
	VmpArchitecture* arch;
	VmpReEngine* reEngine;
};