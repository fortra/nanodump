#pragma once

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);

#define KERNEL32 "Kernel32.dll"
#define LoadLibraryA_SW2_HASH 0x3EBB76B0

PVOID GetFunctionAddress(HMODULE hLibrary, DWORD FunctionHash);
HANDLE GetLibraryAddress(LPCSTR LibName);
