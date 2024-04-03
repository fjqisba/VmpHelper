#pragma once
#include "VmpControlFlow.h"

class VmpFunction
{
public:
	VmpFunction();
	~VmpFunction();
	void FollowVmp(size_t startAddr);
	void CreateGraph();
public:
	size_t startAddr;
private:
	VmpControlFlow cfg;
};