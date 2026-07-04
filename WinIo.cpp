#include "WinIo.h"
#include "physmem.h"
#include "log.h"

WinIo::WinIo() : m_hDev(INVALID_HANDLE_VALUE), m_hScm(NULL), m_hSvc(NULL) {}

WinIo::~WinIo() { Close(); Unload(); }

bool WinIo::Open() {
    m_hDev = CreateFileA(
        "\\\\.\\WinIo",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (m_hDev == INVALID_HANDLE_VALUE) {
        LOG_ERR("WinIo: Open device failed, GLE=%lu", GetLastError());
        return false;
    }
    return true;
}

void WinIo::Close() {
    if (m_hDev != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDev);
        m_hDev = INVALID_HANDLE_VALUE;
    }
}

bool WinIo::Load() {
    wchar_t exeDir[MAX_PATH];
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    wchar_t* last = wcsrchr(exeDir, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(exeDir, L"WinIo64.sys");

    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(100), (LPCWSTR)RT_RCDATA);
    if (hRes) {
        HGLOBAL hGlob = LoadResource(NULL, hRes);
        if (hGlob) {
            DWORD size = SizeofResource(NULL, hRes);
            void* data = LockResource(hGlob);
            if (data && size) {
                HANDLE hFile = CreateFileW(exeDir, GENERIC_WRITE, 0, NULL,
                                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(hFile, data, size, &written, NULL);
                    CloseHandle(hFile);
                    LOG_INFO("WinIo: extracted driver from resources (%lu bytes)", written);
                }
            }
        }
    }

    m_hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!m_hScm) {
        LOG_ERR("WinIo: OpenSCManager failed, GLE=%lu", GetLastError());
        return false;
    }

    m_hSvc = CreateServiceW(m_hScm,
        L"WinIo64",
        L"WinIo64",
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        exeDir,
        NULL, NULL, NULL, NULL, NULL);

    if (!m_hSvc) {
        if (GetLastError() == ERROR_SERVICE_EXISTS)
            m_hSvc = OpenServiceW(m_hScm, L"WinIo64", SERVICE_ALL_ACCESS);
        if (!m_hSvc) {
            LOG_ERR("WinIo: CreateService/OpenService failed, GLE=%lu", GetLastError());
            CloseServiceHandle(m_hScm);
            m_hScm = NULL;
            return false;
        }
    }

    if (!StartServiceW(m_hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_ERR("WinIo: StartService failed, GLE=%lu", err);
            DeleteService(m_hSvc);
            CloseServiceHandle(m_hSvc);
            CloseServiceHandle(m_hScm);
            m_hSvc = NULL;
            m_hScm = NULL;
            return false;
        }
    }

    LOG_OK("WinIo: driver loaded");
    return true;
}

void WinIo::Unload() {
    if (m_hSvc) {
        SERVICE_STATUS status = {};
        ControlService(m_hSvc, SERVICE_CONTROL_STOP, &status);
        DeleteService(m_hSvc);
        CloseServiceHandle(m_hSvc);
        m_hSvc = NULL;
    }
    if (m_hScm) {
        CloseServiceHandle(m_hScm);
        m_hScm = NULL;
    }

    wchar_t driverPath[MAX_PATH];
    GetModuleFileNameW(NULL, driverPath, MAX_PATH);
    wchar_t* last = wcsrchr(driverPath, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(driverPath, L"WinIo64.sys");
    DeleteFileW(driverPath);
}

MappedMemory WinIo::MapPhysicalMemory(ULONG64 physAddr, ULONG64 size) {
    WINIO_MAP_PHYSMEM buf{};
    DWORD returned = 0;

    buf.Size = size;
    buf.PhysAddress = physAddr;

    BOOL ok = DeviceIoControl(
        m_hDev,
        WINIO_IOCTL_MAP_PHYSMEM,
        &buf, sizeof(buf),
        &buf, sizeof(buf),
        &returned,
        nullptr
    );

    if (!ok || returned < sizeof(buf))
        return { nullptr, nullptr, nullptr };

    return { buf.AddrMapped, buf.SectionHandle, buf.ObjPtr };
}

bool WinIo::UnmapPhysicalMemory(HANDLE sectionHandle, void* mappedAddr, void* objPtr) {
    WINIO_UNMAP_PHYSMEM buf{};
    DWORD returned = 0;

    buf.SectionHandle = sectionHandle;
    buf.AddrMapped = mappedAddr;
    buf.ObjPtr = objPtr;

    BOOL ok = DeviceIoControl(
        m_hDev,
        WINIO_IOCTL_UNMAP_PHYSMEM,
        &buf, sizeof(buf),
        &buf, sizeof(buf),
        &returned,
        nullptr
    );

    if (!ok) {
        LOG_ERR("WinIo: UnmapPhysicalMemory(%p) failed, GLE=%lu",
                mappedAddr, GetLastError());
        return false;
    }

    return true;
}

bool WinIo::ReadPhysicalMemory(ULONG64 physAddr, void* buffer, ULONG64 size) {
    if (!size) return true;
    ULONG64 pageOffset = physAddr & 0xFFF;
    ULONG64 alignedPhys = physAddr & ~0xFFFULL;
    ULONG64 mapSize = 0x2000;
    mapSize = (pageOffset + size + 0xFFF) & ~0xFFFULL;

    auto mem = MapPhysicalMemory(alignedPhys, mapSize);
    if (!mem.addr) return false;

    bool bResult = true;
    __try {
        void* readPtr = (void*)((ULONG64)mem.addr + pageOffset);
        memcpy(buffer, readPtr, (size_t)size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bResult = false;
    }

    UnmapPhysicalMemory(mem.sectionHandle, mem.addr, mem.objPtr);
    return bResult;
}

bool WinIo::WritePhysicalMemory(ULONG64 physAddr, const void* buffer, ULONG64 size) {
    if (!size) return true;
    ULONG64 pageOffset = physAddr & 0xFFF;
    ULONG64 alignedPhys = physAddr & ~0xFFFULL;
    ULONG64 mapSize = 0x2000;
    mapSize = (pageOffset + size + 0xFFF) & ~0xFFFULL;

    auto mem = MapPhysicalMemory(alignedPhys, mapSize);
    if (!mem.addr) return false;

    bool bResult = true;
    __try {
        void* writePtr = (void*)((ULONG64)mem.addr + pageOffset);
        memcpy(writePtr, buffer, (size_t)size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bResult = false;
    }

    UnmapPhysicalMemory(mem.sectionHandle, mem.addr, mem.objPtr);
    return bResult;
}

bool WinIo::ReadVirtualMemory(ULONG64 cr3, const void* va, void* buffer, size_t size) {
    if (!size) return false;
    ULONG64 pa = VirtToPhys(this, cr3, (ULONG64)va);
    if(!pa) return false;
    return ReadPhysicalMemory(pa,buffer,size);
}

bool WinIo::WriteVirtualMemory(ULONG64 cr3, void* va, const void* buffer, size_t size) {
    if (!size) return false;
    ULONG64 pa = VirtToPhys(this, cr3, (ULONG64)va);
    if(!pa) return false;
    return WritePhysicalMemory(pa, buffer, size);
}

DWORD WinIo::ReadPort(WORD port, BYTE width) {
    WINIO_PORT_IO input{};
    DWORD output = 0;
    DWORD returned = 0;

    input.PortNumber = port;
    input.Width = width;

    if (width != 1 && width != 2 && width != 4) {
        LOG_ERR("WinIo: ReadPort: invalid width=%u (must be 1/2/4)", width);
        return 0;
    }

    BOOL ok = DeviceIoControl(
        m_hDev,
        WINIO_IOCTL_PORT_READ,
        &input, sizeof(input),
        &output, sizeof(output),
        &returned,
        nullptr
    );

    if (!ok) {
        LOG_ERR("WinIo: ReadPort(0x%X) failed, GLE=%lu", port, GetLastError());
        return 0;
    }

    switch (width) {
        case 1: output &= 0xFF; break;
        case 2: output &= 0xFFFF; break;
    }
    return output;
}

bool WinIo::WritePort(WORD port, DWORD data, BYTE width) {
    WINIO_PORT_IO input{};
    DWORD returned = 0;

    input.PortNumber = port;
    input.Data = data;
    input.Width = width;

    if (width != 1 && width != 2 && width != 4) {
        LOG_ERR("WinIo: WritePort: invalid width=%u (must be 1/2/4)", width);
        return false;
    }

    ULONG64 ret=114514;

    BOOL ok = DeviceIoControl(
        m_hDev,
        WINIO_IOCTL_PORT_WRITE,
        &input, sizeof(input),
        &ret, sizeof(ret),
        &returned,
        nullptr
    );

    LOG_INFO("wte rte=%llx siz=%lx",ret,returned);
    if (!ok) {
        LOG_ERR("WinIo: WritePort(0x%X, 0x%X) failed, GLE=%lu",
               port, data, GetLastError());
        return false;
    }
    return true;
}
