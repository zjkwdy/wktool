#include "kernel.h"
#include "physmem.h"
#include "utils.h"
#include "WinIo.h"
#include "log.h"
#include <cstring>
#include <cctype>
#include <vector>

static WinIo*  g_pWinIo        = nullptr;
static ULONG64 g_KernelBase    = 0;
static ULONG64 g_KernelCr3     = 0;

ULONG64 g_OffUniqueProcessId   = 0x1D0;
ULONG64 g_OffActiveProcessLinks = 0x1D8;
ULONG64 g_OffProtection        = 0x5fA;

bool KVMRead(ULONG64 va, void* buf, size_t size) {
    if (!g_pWinIo || !g_KernelCr3) return false;
    return g_pWinIo->ReadVirtualMemory(g_KernelCr3, (const void*)va, buf, size);
}

bool KVMWrite(ULONG64 va, const void* buf, size_t size) {
    if (!g_pWinIo || !g_KernelCr3) return false;
    return g_pWinIo->WriteVirtualMemory(g_KernelCr3, (void*)va, buf, size);
}

bool InitKernel(WinIo* io) {
    g_pWinIo = io;

    ULONG64 physBase = 0;
    if (!FindKernelPhysBase(io, physBase)) {
        LOG_ERR("InitKernel: kernel physical base not found.");
        return false;
    }

    ULONG64 virtBase = 0, cr3 = 0;
    if (!FindKernelVirtBase(io, physBase, virtBase, cr3)) {
        LOG_ERR("InitKernel: kernel virtual base / CR3 not found.");
        return false;
    }

    g_KernelBase = virtBase;
    g_KernelCr3  = cr3;

    LOG_OK("Kernel basePa=0x%llX baseVa=0x%llX CR3=0x%llX", physBase, g_KernelBase, g_KernelCr3);

    g_CmCallbackList = FindCmCallbackListHead();
    if (g_CmCallbackList)
        LOG_OK("CmCallbackListHead = 0x%llX", g_CmCallbackList);

    return true;
}

ULONG64 GetKernelBase() { return g_KernelBase; }
ULONG64 GetKernelCr3()  { return g_KernelCr3; }

ULONG64 GetSystemRoutineAddress(const wchar_t* name) {
    if (!g_KernelBase) return 0;

    IMAGE_DOS_HEADER dos = {};
    if (!KVMRead(g_KernelBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nth = {};
    if (!KVMRead(g_KernelBase + dos.e_lfanew, &nth, sizeof(nth))) return 0;
    if (nth.Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD exportRva = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return 0;

    ULONG64 exportVA = g_KernelBase + exportRva;
    IMAGE_EXPORT_DIRECTORY expDir = {};
    if (!KVMRead(exportVA, &expDir, sizeof(expDir))) return 0;
    if (!expDir.NumberOfNames || !expDir.AddressOfNames ||
        !expDir.AddressOfNameOrdinals || !expDir.AddressOfFunctions)
        return 0;

    char narrowName[256] = {};
    WideCharToMultiByte(CP_ACP, 0, name, -1, narrowName, (int)sizeof(narrowName) - 1, nullptr, nullptr);

    DWORD* namesRva = (DWORD*)(g_KernelBase + expDir.AddressOfNames);
    WORD*  ordRva   = (WORD*)(g_KernelBase + expDir.AddressOfNameOrdinals);
    DWORD* funcRva  = (DWORD*)(g_KernelBase + expDir.AddressOfFunctions);

    DWORD nameCnt = expDir.NumberOfNames;
    DWORD funcCnt = expDir.NumberOfFunctions;

    std::vector<DWORD> nameBuf(nameCnt);
    std::vector<WORD>  ordBuf(nameCnt);
    std::vector<DWORD> funcBuf(funcCnt);

    if (!KVMRead((ULONG64)namesRva, nameBuf.data(), nameCnt * sizeof(DWORD))) return 0;
    if (!KVMRead((ULONG64)ordRva,   ordBuf.data(),  nameCnt * sizeof(WORD)))  return 0;
    if (!KVMRead((ULONG64)funcRva,  funcBuf.data(), funcCnt * sizeof(DWORD))) return 0;

    for (DWORD i = 0; i < nameCnt; i++) {
        char curName[128] = {};
        if (!KVMRead(g_KernelBase + nameBuf[i], curName, sizeof(curName) - 1))
            continue;
        if (!_stricmp(narrowName, curName))
            return g_KernelBase + funcBuf[ordBuf[i]];
    }
    return 0;
}

ULONG64 GetProcessByPid(DWORD pid) {
    ULONG64 psInitSysProc = GetSystemRoutineAddress(L"PsInitialSystemProcess");
    if (!psInitSysProc) return 0;

    ULONG64 sysEprocess = 0;
    if (!KVMRead(psInitSysProc, &sysEprocess, sizeof(sysEprocess))) return 0;
    if (!sysEprocess) return 0;

    ULONG64 current = sysEprocess;
    do {
        ULONG64 curPid = 0;
        if (!KVMRead(current + g_OffUniqueProcessId, &curPid, sizeof(curPid)))
            break;
        if ((DWORD)curPid == pid)
            return current;

        ULONG64 flink = 0;
        if (!KVMRead(current + g_OffActiveProcessLinks, &flink, sizeof(flink)))
            break;
        current = flink - g_OffActiveProcessLinks;
    } while (current != sysEprocess);

    return 0;
}

static ULONG64 FindOwnCr3(WinIo* io, ULONG64 magicVA, const void* magic, size_t magicLen) {
    const ULONG64 SELF_IDX[] = { 0x1FF, 0x1FE, 0x1FD };
    const int     NUM_IDX    = sizeof(SELF_IDX) / sizeof(SELF_IDX[0]);

    const auto& ranges = GetPhysicalMemoryRanges();

    LOG_INFO("Scanning for own-process CR3...");
    BYTE page[0x1000];

    for (auto& rng : ranges) {
        for (ULONG64 pa = (rng.base + 0xFFF) & ~0xFFFULL; pa < rng.base + rng.size; pa += 0x1000) {
            if (!IsPhysAddrSafe(pa + 0x1000)) break;
            if (!io->ReadPhysicalMemory(pa, page, sizeof(page)))
                continue;

            BOOL valid = FALSE;
            for (int i = 0; i < NUM_IDX; i++) {
                ULONG64 e = *(ULONG64*)(page + SELF_IDX[i] * 8);
                if ((e & PAGE_PRESENT) && ((e & PAGE_PFN_MASK) != 0)) {
                    valid = TRUE;
                    break;
                }
            }
            if (!valid) continue;

            ULONG64 cand = pa & PAGE_PFN_MASK;
            ULONG64 phys = VirtToPhys(io, cand, magicVA);
            if (!phys) continue;

            BYTE probe[64] = {};
            size_t len = magicLen < sizeof(probe) ? magicLen : sizeof(probe);
            if (!io->ReadPhysicalMemory(phys, probe, len))
                continue;
            if (memcmp(probe, magic, len) == 0) {
                LOG_OK("Own-process CR3: 0x%llX", cand);
                return cand;
            }
        }
    }
    return 0;
}

static ULONG64 WalkPml4ForKernelBase(WinIo* io, ULONG64 cr3, ULONG64 kernelPhysBase) {
    ULONG64 pml4Base = cr3 & PAGE_PFN_MASK;
    LOG_INFO("Walking PML4[256..511] for kernel VA -> phys 0x%llX...", kernelPhysBase);

    auto Canon = [](ULONG64 va) -> ULONG64 {
        return (va & (1ULL << 47)) ? (va | 0xFFFF000000000000ULL) : va;
    };

    BYTE pml4[0x1000], pdpt[0x1000], pd[0x1000], pt[0x1000];
    if (!io->ReadPhysicalMemory(pml4Base, pml4, sizeof(pml4))) return 0;

    // ---- Phase 1: 2MB / 1GB large pages only (PDE / PDPTE with PS=1) ----
    LOG_INFO("  Phase 1: scanning large pages...");
    for (int p4 = 256; p4 < 512; p4++) {
        ULONG64 pml4e = ((ULONG64*)pml4)[p4];
        if (!(pml4e & PAGE_PRESENT)) continue;

        if (!io->ReadPhysicalMemory(pml4e & PAGE_PFN_MASK, pdpt, sizeof(pdpt))) continue;
        for (int p3 = 0; p3 < 512; p3++) {
            ULONG64 pdpte = ((ULONG64*)pdpt)[p3];
            if (!(pdpte & PAGE_PRESENT)) continue;

            if (pdpte & PAGE_LARGE) {                               // 1 GB page
                if ((pdpte & PAGE_PFN_MASK) == (kernelPhysBase & ~0x3FFFFFFFULL)) {
                    ULONG64 va = Canon(((ULONG64)p4 << 39) | ((ULONG64)p3 << 30));
                    va += kernelPhysBase & 0x3FFFFFFFULL;
                    va  = Canon(va);
                    LOG_OK("Found kernel virtBase: PML4[%d] PDPT[%d] (1GB page) -> VA 0x%llX", p4, p3, va);
                    return va;
                }
                continue;
            }

            if (!io->ReadPhysicalMemory(pdpte & PAGE_PFN_MASK, pd, sizeof(pd))) continue;
            for (int p2 = 0; p2 < 512; p2++) {
                ULONG64 pde = ((ULONG64*)pd)[p2];
                if (!(pde & PAGE_PRESENT)) continue;

                if (pde & PAGE_LARGE) {                              // 2 MB page
                    if ((pde & PAGE_PFN_MASK) == (kernelPhysBase & ~0x1FFFFFULL)) {
                        ULONG64 va = Canon(((ULONG64)p4 << 39) | ((ULONG64)p3 << 30) | ((ULONG64)p2 << 21));
                        va += kernelPhysBase & 0x1FFFFFULL;
                        va  = Canon(va);
                        LOG_OK("Found kernel virtBase: PML4[%d] PDPT[%d] PD[%d] (2MB page) -> VA 0x%llX", p4, p3, p2, va);
                        return va;
                    }
                }
            }
        }
    }

    // ---- Phase 2: fallback – 4 KB pages (only if no large page matched) ----
    LOG_INFO("  Phase 2: scanning 4KB pages...");
    for (int p4 = 256; p4 < 512; p4++) {
        ULONG64 pml4e = ((ULONG64*)pml4)[p4];
        if (!(pml4e & PAGE_PRESENT)) continue;

        if (!io->ReadPhysicalMemory(pml4e & PAGE_PFN_MASK, pdpt, sizeof(pdpt))) continue;
        for (int p3 = 0; p3 < 512; p3++) {
            ULONG64 pdpte = ((ULONG64*)pdpt)[p3];
            if (!(pdpte & PAGE_PRESENT) || (pdpte & PAGE_LARGE)) continue;

            if (!io->ReadPhysicalMemory(pdpte & PAGE_PFN_MASK, pd, sizeof(pd))) continue;
            for (int p2 = 0; p2 < 512; p2++) {
                ULONG64 pde = ((ULONG64*)pd)[p2];
                if (!(pde & PAGE_PRESENT) || (pde & PAGE_LARGE)) continue;

                if (!io->ReadPhysicalMemory(pde & PAGE_PFN_MASK, pt, sizeof(pt))) continue;
                for (int p1 = 0; p1 < 512; p1++) {
                    ULONG64 pte = ((ULONG64*)pt)[p1];
                    if (!(pte & PAGE_PRESENT)) continue;

                    if ((pte & PAGE_PFN_MASK) == (kernelPhysBase & PAGE_PFN_MASK)) {
                        ULONG64 va = Canon(((ULONG64)p4 << 39) | ((ULONG64)p3 << 30) |
                                           ((ULONG64)p2 << 21) | ((ULONG64)p1 << 12));
                        LOG_OK("Found kernel virtBase: PML4[%d] PDPT[%d] PD[%d] PT[%d] -> VA 0x%llX", p4, p3, p2, p1, va);
                        return va;
                    }
                }
            }
        }
    }

    return 0;
}

bool FindKernelPhysBase(WinIo* io, ULONG64& outPhysBase) {
    if (!io) return false;
    outPhysBase = 0;

    const auto& ranges = GetPhysicalMemoryRanges();
    const ULONG64 PageSize = 0x1000;

    LOG_INFO("Scanning for kernel physical base...");
    for (auto& rng : ranges) {
        LOG_PROGRESS("  Scanning range 0x%llX - 0x%llX ...", rng.base, rng.base + rng.size);

        for (ULONG64 pa = rng.base; pa < rng.base + rng.size; pa += PageSize) {
            WORD magic = 0;
            if (!io->ReadPhysicalMemory(pa, &magic, sizeof(magic)))
                continue;
            if (magic != IMAGE_DOS_SIGNATURE)
                continue;

            IMAGE_DOS_HEADER dosHdr = {};
            if (!io->ReadPhysicalMemory(pa, &dosHdr, sizeof(dosHdr)))
                continue;
            if (dosHdr.e_lfanew > (LONG)(PageSize - sizeof(IMAGE_NT_HEADERS64)))
                continue;

            IMAGE_NT_HEADERS64 ntHdr = {};
            if (!io->ReadPhysicalMemory(pa + dosHdr.e_lfanew, &ntHdr, sizeof(ntHdr)))
                continue;
            if (ntHdr.Signature != IMAGE_NT_SIGNATURE ||
                ntHdr.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
                ntHdr.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE)
                continue;

            ULONG64 baseVa = ntHdr.OptionalHeader.ImageBase;
            if ((baseVa >> 48) != 0xFFFF)
                continue;

            ULONG exportRva = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (exportRva == 0) continue;

            IMAGE_EXPORT_DIRECTORY expDir = {};
            if (!io->ReadPhysicalMemory(pa + exportRva, &expDir, sizeof(expDir)))
                continue;

            char nameBuf[50] = {};
            if (!io->ReadPhysicalMemory(pa + expDir.Name, nameBuf, sizeof(nameBuf) - 1))
                continue;
            for (int k = 0; nameBuf[k]; k++)
                nameBuf[k] = (char)tolower((unsigned char)nameBuf[k]);

            if (!strstr(nameBuf, "ntoskrnl"))
                continue;

            outPhysBase = pa;
            printf("\n");
            LOG_OK("Kernel physical base: 0x%llX", pa);
            return true;
        }
    }

    LOG_ERR("Kernel physical base not found");
    return false;
}

bool FindKernelVirtBase(WinIo* io, ULONG64 physBase, ULONG64& outVirtBase, ULONG64& outCr3) {
    if (!io || !physBase) return false;
    outVirtBase = 0;
    outCr3      = 0;

    // ---- Method 1: read ImageBase from PE header ----
    {
        IMAGE_DOS_HEADER dos = {};
        io->ReadPhysicalMemory(physBase, &dos, sizeof(dos));
        if (dos.e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS64 nt = {};
            io->ReadPhysicalMemory(physBase + dos.e_lfanew, &nt, sizeof(nt));

            ULONG64 ib = nt.OptionalHeader.ImageBase;
            if ((ib >> 48) == 0xFFFF) {
                outVirtBase = ib;
                outCr3 = FindKernelCr3(io, physBase, ib);
                if (outCr3) {
                    LOG_OK("Kernel virtBase (PE ImageBase): 0x%llX", outVirtBase);
                    return true;
                }
            }
        }
    }

    // ---- Method 2: PTE walk via own-process CR3 ----
    LOG_INFO("Method 1 failed; trying PTE walk...");

    const ULONG64 magicVal = 0xCAFEBABEDEADBEEFULL;
    void* magicVA = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!magicVA) {
        LOG_ERR("VirtualAlloc for magic page failed");
        return false;
    }
    memset(magicVA, 0xCC, 0x1000);
    memcpy(magicVA, &magicVal, sizeof(magicVal));

    ULONG64 userCr3 = FindOwnCr3(io, (ULONG64)magicVA, &magicVal, sizeof(magicVal));
    VirtualFree(magicVA, 0, MEM_RELEASE);
    if (!userCr3) {
        LOG_ERR("Own-process CR3 not found");
        return false;
    }

    outVirtBase = WalkPml4ForKernelBase(io, userCr3, physBase);
    if (!outVirtBase) {
        LOG_ERR("Kernel virtual base not found via PML4 walk");
        return false;
    }

    // Get kernel CR3 from EPROCESS of PID 4 (System)
    {
        ULONG64 saveBase = g_KernelBase;
        ULONG64 saveCr3  = g_KernelCr3;
        g_KernelBase = outVirtBase;
        g_KernelCr3  = userCr3;

        ULONG64 pid4Eproc = GetProcessByPid(4);
        if (pid4Eproc) {
            ULONG64 dtb = 0;
            if (KVMRead(pid4Eproc + 0x28, &dtb, sizeof(dtb)) && dtb) {
                outCr3 = dtb;
                LOG_OK("Kernel CR3 from PID 4 EPROCESS: 0x%llX", outCr3);
            }
        }

        g_KernelBase = saveBase;
        g_KernelCr3  = saveCr3;
    }

    if (!outCr3)
        outCr3 = userCr3;

    return true;
}

ULONG64 FindKernelCr3(WinIo* io, ULONG64 kernelPhysBase, ULONG64 kernelVirtBase) {
    const ULONG64 SELF_IDX[]  = { 0x1FF, 0x1FE, 0x1FD };
    const int     NUM_IDX     = sizeof(SELF_IDX) / sizeof(SELF_IDX[0]);

    const auto& ranges = GetPhysicalMemoryRanges();

    LOG_INFO("Scanning for kernel CR3.");
    BYTE page[0x1000];

    for (auto& rng : ranges) {
        LOG_PROGRESS("  Scanning range 0x%llX - 0x%llX ...", rng.base, rng.base + rng.size);
        for (ULONG64 pa = (rng.base + 0xFFF) & ~0xFFFULL; pa < rng.base + rng.size; pa += 0x1000) {

            if (!IsPhysAddrSafe(pa + 0x1000)) break;

            if (!io->ReadPhysicalMemory(pa, page, sizeof(page)))
                continue;

            BOOL valid = FALSE;
            ULONG64 selfPfn = 0;
            for (int i = 0; i < NUM_IDX; i++) {
                ULONG64 e = *(ULONG64*)(page + SELF_IDX[i] * 8);
                if ((e & PAGE_PRESENT) && ((e & PAGE_PFN_MASK) != 0)) {
                    valid = TRUE;
                    selfPfn = e & PAGE_PFN_MASK;
                    break;
                }
            }
            if (!valid) continue;

            if (!IsPhysAddrSafe(selfPfn)) continue;

            ULONG64 cand = pa & PAGE_PFN_MASK;
            ULONG64 trans = VirtToPhys(io, cand, kernelVirtBase);
            if (trans == kernelPhysBase) {
                printf("\n");
                return cand;
            }
        }
    }

    printf("\n");
    LOG_ERR("Kernel CR3 not found");
    return 0;
}

ULONG64 GetImportedDllFunctionViaIDT(const wchar_t* dllName, const wchar_t* funcName) {
    if (!g_KernelBase) return 0;

    IMAGE_DOS_HEADER dos = {};
    if (!KVMRead(g_KernelBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nth = {};
    if (!KVMRead(g_KernelBase + dos.e_lfanew, &nth, sizeof(nth))) return 0;
    if (nth.Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD importRva = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return 0;
    ULONG64 importVA = g_KernelBase + importRva;

    char narrowFunc[256] = {};
    WideCharToMultiByte(CP_ACP, 0, funcName, -1, narrowFunc, (int)sizeof(narrowFunc) - 1, nullptr, nullptr);

    char narrowDll[256] = {};
    WideCharToMultiByte(CP_ACP, 0, dllName, -1, narrowDll, (int)sizeof(narrowDll) - 1, nullptr, nullptr);
    _strlwr_s(narrowDll);

    LOG_INFO("Searching import table for '%hs!%hs'...", narrowDll, narrowFunc);

    for (int idx = 0; ; idx++) {
        IMAGE_IMPORT_DESCRIPTOR imp = {};
        if (!KVMRead(importVA + idx * sizeof(imp), &imp, sizeof(imp)))
            return 0;
        if (!imp.Name && !imp.FirstThunk)
            break;

        char curDllName[64] = {};
        if (!KVMRead(g_KernelBase + imp.Name, curDllName, sizeof(curDllName) - 1))
            continue;
        curDllName[sizeof(curDllName) - 1] = '\0';
        _strlwr_s(curDllName);

        if (!strstr(curDllName, narrowDll))
            continue;

        LOG_OK("Found '%hs' import descriptor at index %d", curDllName, idx);

        ULONG64 iatVA = g_KernelBase + (imp.FirstThunk ? imp.FirstThunk : imp.OriginalFirstThunk);
        ULONG64 intVA = g_KernelBase + imp.OriginalFirstThunk;

        for (int fi = 0; ; fi++) {
            ULONG64 thunk = 0;
            if (!KVMRead(intVA + fi * sizeof(thunk), &thunk, sizeof(thunk)))
                break;
            if (!thunk) break;

            if (thunk & IMAGE_ORDINAL_FLAG64) {
                continue;
            }

            IMAGE_IMPORT_BY_NAME ibn = {};
            if (!KVMRead(g_KernelBase + (DWORD)thunk, &ibn, sizeof(ibn)))
                continue;

            char importName[128] = {};
            if (!KVMRead(g_KernelBase + (DWORD)thunk + sizeof(WORD),
                         importName, sizeof(importName) - 1))
                continue;
            importName[sizeof(importName) - 1] = '\0';

            if (_stricmp(narrowFunc, importName) != 0)
                continue;

            ULONG64 funcAddr = 0;
            if (!KVMRead(iatVA + fi * sizeof(funcAddr), &funcAddr, sizeof(funcAddr)))
                return 0;

            LOG_OK("'%hs!%hs' = 0x%llX", curDllName, importName, funcAddr);
            return funcAddr;
        }

        LOG_ERR("Function '%hs' not found in '%hs' imports", narrowFunc, curDllName);
        return 0;
    }

    LOG_ERR("DLL matching '%hs' not found in imports", narrowDll);
    return 0;
}
