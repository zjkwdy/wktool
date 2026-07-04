#pragma once
#include <cstdint>
#include <windows.h>
#include <vector>

class WinIo;

struct PhysMemRange {
    ULONG64 base;
    ULONG64 size;
};

constexpr ULONG64 PAGE_PRESENT  = 0x001;
constexpr ULONG64 PAGE_LARGE    = 0x080;
constexpr ULONG64 PAGE_NX       = 0x8000000000000000ULL;
constexpr ULONG64 PAGE_PFN_MASK = 0x0000FFFFFFFFF000ULL;

ULONG64 VirtToPhys(WinIo* io, ULONG64 cr3, ULONG64 virtAddr);
bool    IsPhysAddrSafe(ULONG64 pa);
const std::vector<PhysMemRange>& GetPhysicalMemoryRanges();
