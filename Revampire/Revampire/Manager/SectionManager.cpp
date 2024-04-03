#include "SectionManager.h"
#include <segment.hpp>
#include <bytes.hpp>

static size_t AlignByMemory(size_t originValue, size_t alignment)
{
	size_t reminder = originValue / alignment;
	size_t mod = originValue % alignment;
	if (mod != 0) {
		reminder += 1;
	}
	return reminder * alignment;
}

SectionManager& SectionManager::Main()
{
	static SectionManager gMainSection;
	return gMainSection;
}

SectionManager::SectionManager()
{
	InitSectionManager();
}

bool SectionManager::InitSectionManager()
{
	segList.clear();
	int segCount = get_segm_qty();
	unsigned int bufSize = 0;
	for (int idx = 0; idx < segCount; ++idx)
	{
		SegmentInfomation tmpInfo;
		segment_t* pSegment = getnseg(idx);
		tmpInfo.segStart = pSegment->start_ea;
		tmpInfo.segSize = pSegment->size();
		bufSize += tmpInfo.segSize;
		qstring tmpSectionName;
		get_segm_name(&tmpSectionName, pSegment);
		tmpInfo.segName = std::string(tmpSectionName.c_str(), tmpSectionName.length());
		tmpInfo.segData.resize(pSegment->size());
		get_bytes(&tmpInfo.segData[0], pSegment->size(), pSegment->start_ea, GMB_READALL);
		segList.push_back(tmpInfo);
	}
	return true;
}

unsigned char* SectionManager::LinearAddrToVirtualAddr(size_t LinerAddr)
{
	unsigned int index = saveIndex;
	for (unsigned int n = 0; n < segList.size(); ++n) {
		unsigned int endAddr = segList[index].segStart + segList[index].segSize;
		if (LinerAddr >= segList[index].segStart && LinerAddr < endAddr) {
			unsigned int offset = LinerAddr - segList[index].segStart;
			saveIndex = index;
			return &segList[index].segData[offset];
		}
		++index;
		if (index == segList.size()) {
			index = 0;
		}
	}
	return 0;
}

int SectionManager::SectionIndex(size_t addr)
{
	for (unsigned int n = 0; n < segList.size(); ++n) {
		if (addr >= segList[n].segStart && addr < segList[n].segStart + segList[n].segSize) {
			return n;
		}
	}
	return -1;
}