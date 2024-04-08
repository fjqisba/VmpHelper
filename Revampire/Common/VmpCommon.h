#pragma once
#include <tuple>

struct VmAddress
{
	size_t raw;
	size_t vmdata;
	VmAddress() {
		raw = 0x0;
		vmdata = 0x0;
	}
	VmAddress(size_t ins, size_t vm) {
		raw = ins;
		vmdata = vm;
	}
	VmAddress(size_t ins) {
		raw = ins;
		vmdata = 0x0;
	}
	bool operator<(const VmAddress& other) const
	{
		return std::tie(raw, vmdata) < std::tie(other.raw, other.vmdata);
	}
};