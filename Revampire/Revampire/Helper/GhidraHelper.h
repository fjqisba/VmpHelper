#pragma once
#include <map>
#include <vector>
#include <string>
#include <set>

//这里面包含了一些对Ghidra操作的封装

namespace ghidra
{
    class Funcdata;
    class Varnode;
    class PcodeOp;
    struct VarnodeData;
}

namespace GhidraHelper
{

	struct TraceResult
	{
		TraceResult() {
			addr = 0x0;
			bAccessMem = false;
			offset = 0x0;
		}
		//结果名
		std::string name;
		//输入的指令地址
		size_t addr;
		//是否为访问内存
		bool bAccessMem;
		//varnode的偏移地址
		std::uint64_t offset;
		bool operator<(const TraceResult& other) const {
			if (addr != other.addr) {
				return addr < other.addr;
			}
			if (bAccessMem != other.bAccessMem) {
				return bAccessMem < other.bAccessMem;
			}
			if (offset != other.offset) {
				return offset < other.offset;
			}
			return name < other.name;
		}
	};

    class PcodeOpTracer
    {
    public:
        PcodeOpTracer(ghidra::Funcdata* f) { fd = f; };
        ~PcodeOpTracer() {};
        std::vector<TraceResult> TraceInput(size_t startAddr, ghidra::Varnode* vn);
    private:
        void traceNode(size_t opAddr, ghidra::Varnode* vn, bool bAccessMem, std::vector<TraceResult>& outResult);
        void traceOpCode(ghidra::PcodeOp* op, bool bAccessMem, std::vector<TraceResult>& outResult);
    private:
        ghidra::Funcdata* fd;
        std::set<TraceResult> filterResult;
    };


	class VmpBranchExtractor
	{
	public:
		std::vector<size_t> ExtractVmAllBranch(ghidra::Funcdata* fd);
	private:
		void checkBranchPattern(ghidra::PcodeOp* curOp);
	private:
		std::vector<size_t> branchList;
		std::vector<ghidra::PcodeOp*> anaList;
	};

	std::string GetVarnodeRegName(ghidra::Varnode* vn);
}