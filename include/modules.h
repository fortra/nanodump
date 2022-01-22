#pragma once

#include <windows.h>
#include <winternl.h>

#include "output.h"
#include "syscalls.h"
#include "ntdefs.h"
#include "utils.h"

#define LSASRV_DLL L"lsasrv.dll"
#ifdef _WIN64
#define LDR_POINTER_OFFSET 0x18
#define MODULE_LIST_POINTER_OFFSET 0x20
#else
#define LDR_POINTER_OFFSET 0xc
#define MODULE_LIST_POINTER_OFFSET 0x14
#endif

typedef struct _module_info
{
    struct _module_info* next;
    ULONG64 dll_base;
    ULONG32 size_of_image;
    char dll_name[256];
    ULONG32 name_rva;
    ULONG32 TimeDateStamp;
    ULONG32 CheckSum;
} module_info, *Pmodule_info;

Pmodule_info find_modules(HANDLE hProcess, wchar_t* important_modules[], int number_of_important_modules, BOOL is_lsass);
