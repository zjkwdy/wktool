#pragma once
#include <cstdint>
#include <windows.h>

extern ULONG64 g_OffCallbackList;
extern ULONG64 g_CmCallbackList;
extern ULONG64 g_OffToken;

bool     SetPPL(DWORD pid, int protection);
bool     DisableObTypeCallbacks(const wchar_t* typeName);
ULONG64  FindCmCallbackListHead();
bool     RemoveCmCallback();

ULONG64  GetProcessToken(ULONG64 eprocess);
bool     SetProcessToken(ULONG64 eprocess, ULONG64 token);
bool     StealToken(DWORD srcPid, DWORD dstPid);
bool     SetTokenPrivileges(DWORD pid, ULONG64 privMask);
bool     DisableDriverSignature();
bool     RestoreDriverSignature();
