#pragma once

#include <windows.h>
#include <winternl.h>

#include "utils.h"

#define LdrLoadDll_SW2_HASH 0xA301ECDA

#define MZ 0x5A4D

typedef NTSTATUS(WINAPI* LdrLoadDll_t)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

typedef struct _ND_LDR_DATA_TABLE_ENTRY
{
    //struct _LIST_ENTRY InLoadOrderLinks;
    struct _LIST_ENTRY InMemoryOrderLinks;
    struct _LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} ND_LDR_DATA_TABLE_ENTRY, *PND_LDR_DATA_TABLE_ENTRY;

typedef struct _ND_PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    struct _LIST_ENTRY InLoadOrderModuleList;
    struct _LIST_ENTRY InMemoryOrderModuleList;
    struct _LIST_ENTRY InInitializationOrderModuleList;
} ND_PEB_LDR_DATA, *PND_PEB_LDR_DATA;

typedef struct _ND_PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PND_PEB_LDR_DATA Ldr;
} ND_PEB, *PND_PEB;

BOOL is_dll(
    IN HMODULE hLibrary);

PVOID find_legacy_export(
    IN HMODULE hOriginalLibrary,
    IN DWORD fhash);

PVOID resolve_reference(
    IN HMODULE hOriginalLibrary,
    IN PVOID addr);

PVOID get_function_address(
    IN HMODULE hLibrary,
    IN DWORD fhash,
    IN WORD ordinal);

HANDLE get_library_address(
    IN LPWSTR lib_path,
    IN BOOL DoLoad);

