#pragma once
#include <windows.h>
#include <cstdint>

#pragma pack(push, 1)

#define WINIO_IOCTL_MAP_PHYSMEM   0x80102040
#define WINIO_IOCTL_UNMAP_PHYSMEM 0x80102044
#define WINIO_IOCTL_PORT_READ     0x80102050
#define WINIO_IOCTL_PORT_WRITE    0x80102054

typedef struct _WINIO_MAP_PHYSMEM {
    ULONG64  Size;
    ULONG64  PhysAddress;
    HANDLE   SectionHandle;
    void*    AddrMapped;
    void*    ObjPtr;
} WINIO_MAP_PHYSMEM;

typedef struct _WINIO_UNMAP_PHYSMEM {
    ULONG64  Reserved1;
    ULONG64  Reserved2;
    HANDLE   SectionHandle;
    void*    AddrMapped;
    void*    ObjPtr;
} WINIO_UNMAP_PHYSMEM;

typedef struct _WINIO_PORT_IO {
    WORD     PortNumber;
    DWORD    Data;
    BYTE     Width;
} WINIO_PORT_IO;

#pragma pack(pop)

static_assert(sizeof(WINIO_MAP_PHYSMEM) == 40, "WINIO_MAP_PHYSMEM must be 40 bytes");
static_assert(sizeof(WINIO_UNMAP_PHYSMEM) == 40, "WINIO_UNMAP_PHYSMEM must be 40 bytes");
static_assert(sizeof(WINIO_PORT_IO) == 7, "WINIO_PORT_IO must be 7 bytes");

struct MappedMemory {
    void*   addr;
    HANDLE  sectionHandle;
    void*   objPtr;
};

class WinIo {
public:
    WinIo();
    ~WinIo();

    bool Open();
    void Close();
    bool IsOpen() const { return m_hDev != INVALID_HANDLE_VALUE; }

    bool Load();
    void Unload();

    MappedMemory MapPhysicalMemory(ULONG64 physAddr, ULONG64 size);
    bool UnmapPhysicalMemory(HANDLE sectionHandle, void* mappedAddr, void* objPtr);
    bool ReadPhysicalMemory(ULONG64 physAddr, void* buffer, ULONG64 size);
    bool WritePhysicalMemory(ULONG64 physAddr, const void* buffer, ULONG64 size);

    DWORD ReadPort(WORD port, BYTE width);
    bool WritePort(WORD port, DWORD data, BYTE width);

    template<typename T>
    T ReadPhys(ULONG64 physAddr) {
        T val{};
        ReadPhysicalMemory(physAddr, &val, sizeof(T));
        return val;
    }

    bool ReadVirtualMemory(ULONG64 cr3, const void* va,
                           void* buffer, size_t size);
    bool WriteVirtualMemory(ULONG64 cr3, void* va,
                            const void* buffer, size_t size);

private:
    HANDLE m_hDev;
    SC_HANDLE m_hScm;
    SC_HANDLE m_hSvc;
};
