#pragma once

#include <windows.h>
#include <winternl.h>

#include "output.h"
#include "syscalls.h"
#include "ntdefs.h"
#include "utils.h"

#define UNUSED(x) (void)(x)

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
    char dll_name[512];
    ULONG32 name_rva;
    ULONG32 TimeDateStamp;
    ULONG32 CheckSum;
} module_info, *Pmodule_info;

PVOID get_peb_address(
    IN HANDLE hProcess);

PVOID get_module_list_address(
    IN HANDLE hProcess,
    IN BOOL is_lsass);

Pmodule_info add_new_module(
    IN HANDLE hProcess,
    IN struct LDR_DATA_TABLE_ENTRY* ldr_entry);

BOOL read_ldr_entry(
    IN HANDLE hProcess,
    IN PVOID ldr_entry_address,
    OUT struct LDR_DATA_TABLE_ENTRY* ldr_entry,
    OUT wchar_t* base_dll_name);

Pmodule_info find_modules(
    IN HANDLE hProcess,
    IN wchar_t* important_modules[],
    IN int number_of_important_modules,
    IN BOOL is_lsass);
