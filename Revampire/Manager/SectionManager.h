#pragma once
#include <string>
#include <vector>

struct SegmentInfomation
{
	size_t segStart;					  //区段起始地址
	size_t segSize;						  //区段大小
	std::string segName;                  //区段名称
	std::vector<unsigned char> segData;   //区段数据
};

class SectionManager
{
public:
	SectionManager();
	static SectionManager& Main();
	bool InitSectionManager();
	//线性地址转换为虚拟地址
	unsigned char* LinearAddrToVirtualAddr(size_t LinerAddr);
	//判断当前地址在哪个区段
	int SectionIndex(size_t addr);
public:
	std::vector<SegmentInfomation> segList;
	//存储上一次命中的索引,用于加速访问
	int saveIndex = 0x0;
};