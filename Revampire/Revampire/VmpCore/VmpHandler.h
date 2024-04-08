#pragma once
#include "../Ghidra/pcoderaw.hh"

namespace ghidra
{
    class Funcdata;
}

namespace GhidraHelper
{
	struct TraceResult;
}

class VmpNode;
class VmpArchitecture;
class VmpBlockWalker;
class VmpBasicBlock;

class VmpRegStatus
{
public:
	//vm字节码寄存器
	std::string vmCodeReg;
	//vm虚拟堆栈寄存器
	std::string vmStackReg;
	//是否已选择好了寄存器
	bool isSelected;
};

//vmp分析数据

class VmpBlockBuildContext
{
public:
	enum BUILD_RET
	{
		//继续匹配
		BUILD_CONTINUE = 0x0,
		//合并匹配
		BUILD_MERGE,
		//退出
		BUILD_EXIT,
	};
	enum VM_MATCH_STATUS {
		FIND_VM_INIT = 0x0,
		FINISH_VM_INIT = 0x1,
	};
public:
	VmpRegStatus vmReg;
	VM_MATCH_STATUS status;
	VmpBasicBlock* bBlock;
	BUILD_RET ret;
};

struct VmpHandlerRange
{
    size_t startAddr;
    size_t endAddr;
    std::uint64_t hash;
    VmpHandlerRange(VmpNode& nodeInput);
    bool operator<(const VmpHandlerRange& other) const
    {
        return std::tie(startAddr, endAddr, hash) < std::tie(other.startAddr, other.endAddr, other.hash);
    }
private:
    std::uint64_t NodeHash(VmpNode& nodeInput);
};

class VmpHandlerFactory
{
public:
    VmpHandlerFactory(VmpArchitecture* re);
    ~VmpHandlerFactory() {};
public:
    bool BuildVmpBlock(VmpBlockBuildContext* buildData,VmpBlockWalker& walker);
private:
	void ExecuteVmpPattern(VmpNode& nodeInput);
	bool Execute_FIND_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd);
	bool Execute_FINISH_VM_INIT(VmpNode& nodeInput, ghidra::Funcdata* fd);
	bool tryMatch_vPopReg(std::vector<GhidraHelper::TraceResult>& dstResult, std::vector<GhidraHelper::TraceResult>& srcResult);
private:
	VmpBlockBuildContext* buildContext;
private:
    VmpBlockWalker* walker;
    VmpArchitecture* arch;
};