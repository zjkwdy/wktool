#include "log.h"
#include "physmem.h"
#include "WinIo.h"
#include <vector>
#include <algorithm>

static_assert(sizeof(ULONG64) == 8, "ULONG64 must be 8 bytes");

const std::vector<PhysMemRange>& GetPhysicalMemoryRanges() {
    static std::vector<PhysMemRange> s_ranges;
    if (!s_ranges.empty())
        return s_ranges;

    std::vector<PhysMemRange>& ranges = s_ranges;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        goto fallback;

    {
        DWORD type = 0, cbData = 0;
        if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, nullptr, &cbData) != ERROR_SUCCESS
            || type != REG_RESOURCE_LIST) {
            RegCloseKey(hKey);
            goto fallback;
        }

        BYTE* buf = (BYTE*)malloc(cbData);
        if (!buf) { RegCloseKey(hKey); goto fallback; }

        if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, buf, &cbData) != ERROR_SUCCESS) {
            free(buf);
            RegCloseKey(hKey);
            goto fallback;
        }
        RegCloseKey(hKey);

        const size_t DESCSIZE = 20;
        size_t pos = 0;
        if (pos + 4 <= cbData) {
            ULONG count = *((ULONG*)(buf + pos)); pos += 4;

            for (ULONG i = 0; i < count && pos + 8 <= cbData; i++) {
                pos += 8;

                if (pos + 8 > cbData) break;
                ULONG descCount = *((ULONG*)(buf + pos + 4)); pos += 8;

                for (ULONG j = 0; j < descCount && pos + DESCSIZE <= cbData; j++) {
                    UCHAR resType = buf[pos];
                    pos += 4;

                    if (resType == 3) {
                        ULONG64 start = *((ULONG64*)(buf + pos));
                        ULONG   len   = *((ULONG*)(buf + pos + 8));
                        if (len > 0)
                            ranges.push_back({start, (ULONG64)len});
                    } else if (resType == 7) {
                        ULONG64 start = *((ULONG64*)(buf + pos));
                        ULONG   len   = *((ULONG*)(buf + pos + 8));
                        if (len > 0)
                            ranges.push_back({start, (ULONG64)len * 0x100});
                    }
                    pos += 16;
                }
            }
        }
        free(buf);
    }

    if (!ranges.empty()) {
        std::sort(ranges.begin(), ranges.end(),
            [](const PhysMemRange& a, const PhysMemRange& b) { return a.base < b.base; });
        LOG_INFO("Got %zu physical memory range(s):", ranges.size());
        for (auto& r : ranges)
            LOG_INFO("  0x%08llX - 0x%08llX  (%llu MB)",
                    r.base, r.base + r.size, r.size >> 20);
        
        return ranges;
    }

fallback:
    {
        ULONG64 kb = 0;
        if (GetPhysicallyInstalledSystemMemory(&kb) && kb) {
            ULONG64 bytes = (ULONG64)kb << 10;
            if (bytes > 0x200000000ULL) bytes = 0x200000000ULL;
            ranges.push_back({0x1000, bytes - 0x1000});
        } else {
            ranges.push_back({0x1000, 0x40000000ULL - 0x1000});
        }
    }
    return ranges;
}

bool IsPhysAddrSafe(ULONG64 pa) {
    for (auto& r : GetPhysicalMemoryRanges())
        if (pa >= r.base && pa < r.base + r.size)
            return true;
    return false;
}

/*
 * x64 4-level paging walk:
 *
 *  Virtual address (48-bit canonical):
 *   [47:39]  ─ PML4 index  (9 bits)
 *   [38:30]  ─ PDPT index  (9 bits)
 *   [29:21]  ─ PD   index  (9 bits)
 *   [20:12]  ─ PT   index  (9 bits)
 *   [11:0]   ─ page offset (12 bits)
 *
 *  Each table is 4 KB (512 entries × 8 bytes).
 *  Entry format:
 *   [63:52] available / flags
 *   [51:12] physical page frame number (PFN)
 *   [11:0]  flags (Present=bit0, RW=bit1, US=bit2, PWT=bit3, PCD=bit4,
 *                   Accessed=bit5, Dirty=bit6, Large=bit7, Global=bit8, NX=bit63)
 *
 *  Large pages:
 *   1 GB: PDPT entry with Large bit set → uses bits [47:30] for PFN, [29:0] for offset
 *   2 MB: PD   entry with Large bit set → uses bits [47:21] for PFN, [20:0] for offset
 */
ULONG64 VirtToPhys(WinIo* io, ULONG64 cr3, ULONG64 virtAddr) {
    if (!io) return 0;

    ULONG64 pml4Base = cr3 & PAGE_PFN_MASK;
    if (pml4Base == 0 || !IsPhysAddrSafe(pml4Base)) return 0;

#define READ_PTE(tablePa, idx, dst) do {                                 \
    ULONG64 __pa = (tablePa) + (ULONG64)(idx) * 8;                       \
    if (!IsPhysAddrSafe(__pa)) return 0;                                 \
    if (!io->ReadPhysicalMemory(__pa, &(dst), sizeof(dst))) return 0;    \
    if (!((dst) & PAGE_PRESENT)) return 0;                               \
} while (0)

    ULONG64 pml4e = 0;
    READ_PTE(pml4Base, (virtAddr >> 39) & 0x1FF, pml4e);
    ULONG64 pdptBase = pml4e & PAGE_PFN_MASK;

    ULONG64 pdpte = 0;
    READ_PTE(pdptBase, (virtAddr >> 30) & 0x1FF, pdpte);
    if (pdpte & PAGE_LARGE) {
        return (pdpte & (PAGE_PFN_MASK & ~((1ULL << 30) - 1)))
             | (virtAddr & 0x3FFFFFFF);
    }
    ULONG64 pdBase = pdpte & PAGE_PFN_MASK;

    ULONG64 pde = 0;
    READ_PTE(pdBase, (virtAddr >> 21) & 0x1FF, pde);
    if (pde & PAGE_LARGE) {
        return (pde & (PAGE_PFN_MASK & ~((1ULL << 21) - 1)))
             | (virtAddr & 0x1FFFFF);
    }
    ULONG64 ptBase = pde & PAGE_PFN_MASK;

    ULONG64 pte = 0;
    READ_PTE(ptBase, (virtAddr >> 12) & 0x1FF, pte);

#undef READ_PTE

    return (pte & PAGE_PFN_MASK) | (virtAddr & 0xFFF);
}
