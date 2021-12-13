#pragma once

#define MAX_HANDLES 10000
#define INVALID_HANDLE 6

#define ADVAPI32 "Advapi32.dll"
#define CreateProcessWithLogonW_SW2_HASH 0x39A92305

typedef struct _HANDLE_LIST
{
    ULONG Count;
    HANDLE Handle[MAX_HANDLES];
} HANDLE_LIST, *PHANDLE_LIST;

struct TEB
{
    struct _NT_TIB NtTib;
    VOID* EnvironmentPointer;
    struct _CLIENT_ID ClientId;
    VOID* ActiveRpcHandle;
    VOID* ThreadLocalStoragePointer;
    struct _PEB* ProcessEnvironmentBlock;
};

typedef BOOL(WINAPI* CREATEPROCESSWITHLOGONW) (LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL seclogon_stage_1(LPCSTR program_name, LPCSTR dump_name, BOOL fork, BOOL valid, BOOL use_seclogon_locally, DWORD lsass_pid, PPROCESS_LIST process_list);
#ifndef BOF
HANDLE seclogon_stage_2(LPCSTR dump_path);
#endif
