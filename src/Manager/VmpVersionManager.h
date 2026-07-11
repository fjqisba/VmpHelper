#pragma once
#include "../Common/Public.h"

//管理vmp的版本
//对于目前来说，比起编写通用的去vmp化脚本,或许针对vmp的版本编写特定脚本会更好

class VmpVersionManager
{
public:
	enum VmpVersion {
		VMP_UNKNOWN = 0x0,
		VMP_350,
		VMP_380,
	};
	static void SetVmpVersion(VmpVersion v) { ver = v; };
	static VmpVersion CurrentVmpVersion() { return ver; };
public:
	static VmpVersion ver;
};