#pragma once

#include <windows.h>
#include <winternl.h>

#include "utils.h"
#include "dinvoke.h"
#include "handle.h"
#include "syscalls.h"
#include "ppl/ppl_utils.h"
#include "ppl/ppl_medic.h"
#include "ppl/ppl.h"

#define LdrGetKnownDllSectionHandle_SW2_HASH 0xABB7D960

typedef RPC_STATUS(WINAPI*  UuidToStringW_t)(UUID *Uuid, RPC_WSTR *StringUuid);
typedef RPC_STATUS(WINAPI*  RpcStringFreeW_t)(RPC_WSTR *String);
typedef PIMAGE_NT_HEADERS(NTAPI* RtlImageNtHeader_t)(PVOID ModuleAddress);

#define UuidToStringW_SW2_HASH      0x0A907D4E
#define RpcStringFreeW_SW2_HASH     0x0C953D0F
#define RtlImageNtHeader_SW2_HASH   0x00BCFBB5

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define SYMBOLIC_LINK_QUERY 0x0001

#if defined(_MSC_VER)

#define FileStandardInformation 5
#define ThreadImpersonationToken 5

typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG         NumberOfLinks;
  BOOLEAN       DeletePending;
  BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

#endif

BOOL is_win_6_point_3_or_grater(VOID);

BOOL is_win_10_or_grater(VOID);

BOOL object_manager_create_directory(
    IN LPWSTR dirname,
    OUT PHANDLE hDirectory);

BOOL object_manager_create_symlik(
    IN LPWSTR linkname,
    IN LPWSTR targetname,
    OUT PHANDLE hLink);

BOOL check_known_dll_symbolic_link(
    IN LPCWSTR pwszDllName,
    IN LPWSTR pwszTarget);

BOOL get_file_size(
    IN HANDLE hFile,
    OUT PDWORD file_size);

VOID safe_close_handle(
    IN PHANDLE Handle);

BOOL get_hijacked_dll_name(
    OUT LPWSTR* HijackedDllName,
    OUT LPWSTR* HijackedDllSectionPath);

BOOL find_writable_system_dll(
    IN DWORD MinSize,
    OUT LPWSTR* FilePath);

BOOL get_known_dlls_handle_address(
    IN PVOID* KnownDllDirectoryHandleAddr);

BOOL set_registry_string_value(
    IN HKEY Key,
    IN LPCWSTR SubKey,
    IN LPCWSTR ValueName,
    IN LPCWSTR ValueData);

BOOL get_type_lib_reg_value_path(
    IN LPWSTR* TypeLibRegValuePath);

BOOL get_registry_string_value(
    IN HKEY Key,
    IN LPCWSTR SubKey,
    IN LPCWSTR ValueName,
    OUT LPWSTR* ValueData);

VOID safe_release(
    IN IUnknown** Interface);

BOOL generate_temp_path(
    OUT LPWSTR* Buffer);

BOOL get_service_process_id(
    IN LPCWSTR ServiceName,
    OUT LPDWORD ProcessId);

BOOL query_service_status_process_by_handle(
    IN SC_HANDLE ServiceHandle,
    IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus);

BOOL get_service_handle(
    IN LPCWSTR ServiceName,
    IN DWORD DesiredAccess,
    OUT LPSC_HANDLE ServiceHandle);

BOOL query_service_status_process_by_name(
    IN LPCWSTR ServiceName,
    IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus);

BOOL get_service_status_by_name(
    IN LPCWSTR ServiceName,
    OUT LPDWORD Status);

BOOL stop_service_by_name(
    IN LPCWSTR ServiceName,
    IN BOOL Wait);

BOOL start_service_by_name(
    IN LPCWSTR ServiceName,
    IN BOOL Wait);

VOID safe_free(
    IN PVOID* Memory);

BOOL get_windows_temp_directory(
    OUT LPWSTR* Path);

BOOL find_module_section(
    IN HMODULE Module,
    IN LPCSTR SectionName,
    OUT PULONG_PTR Address,
    OUT LPDWORD Size);

BOOL find_module_pattern(
    IN PBYTE Pattern,
    IN DWORD PatternLength,
    IN ULONG_PTR Address,
    IN DWORD Size,
    OUT PULONG_PTR PatternAddress);

BOOL is_service_running(
    IN LPCWSTR ServiceName);

BOOL delete_directory(
    IN LPWSTR Path);
