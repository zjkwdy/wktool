#pragma once
#include <cstdint>
#include <windows.h>

class WinIo;

extern ULONG64 g_OffUniqueProcessId;
extern ULONG64 g_OffActiveProcessLinks;
extern ULONG64 g_OffProtection;

bool     InitKernel(WinIo* io);
ULONG64  GetKernelBase();
ULONG64  GetKernelCr3();
ULONG64  GetSystemRoutineAddress(const wchar_t* name);
bool     KVMRead(ULONG64 va, void* buf, size_t size);
bool     KVMWrite(ULONG64 va, const void* buf, size_t size);
ULONG64  GetProcessByPid(DWORD pid);
bool     FindKernelPhysBase(WinIo* io, ULONG64& outPhysBase);
bool     FindKernelVirtBase(WinIo* io, ULONG64 physBase, ULONG64& outVirtBase, ULONG64& outCr3);
ULONG64  FindKernelCr3(WinIo* io, ULONG64 kernelPhysBase, ULONG64 kernelVirtBase);
ULONG64  GetImportedDllFunctionViaIDT(const wchar_t* dllName, const wchar_t* funcName);
