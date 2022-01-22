#pragma once

#include <windows.h>
#include <winternl.h>

#include "nanodump.h"
#include "handle.h"
#include "dinvoke.h"

#if defined(NANO) && !defined(SSP)

#define MAX_HANDLES 10000
#define INVALID_HANDLE 6

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

typedef BOOL(WINAPI* CreateProcessWithLogonW_t) (LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

void kill_created_processes(PPROCESS_LIST created_processes);
BOOL MalSecLogon(LPCSTR binary_path, LPCSTR dump_path, BOOL fork, BOOL use_valid_sig, BOOL use_malseclogon_locally, DWORD lsass_pid, PPROCESS_LIST* Pcreated_processes);
BOOL malseclogon_stage_1(LPCSTR program_name, LPCSTR dump_path, BOOL fork_lsass, BOOL valid, BOOL use_malseclogon_locally, DWORD lsass_pid, PPROCESS_LIST process_list);
#ifdef EXE
HANDLE malseclogon_stage_2(LPCSTR dump_path);
#endif

#endif
