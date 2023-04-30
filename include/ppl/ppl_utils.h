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
typedef BOOL(WINAPI* ControlService_t)(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
typedef PVOID(WINAPI* Sleep_t)(DWORD dwMilliseconds);
typedef DWORD(WINAPI* GetCurrentDirectoryW_t)(DWORD nBufferLength, LPWSTR lpBuffer);
typedef BOOL(WINAPI* SetCurrentDirectoryW_t)(LPCWSTR lpPathName);
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef DWORD(WINAPI* GetFileSize_t)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef BOOL(WINAPI* StartServiceW_t)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR *lpServiceArgVectors);
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LSTATUS(WINAPI* RegQueryValueExW_t)(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
typedef DWORD(WINAPI* GetTempPathW_t)(DWORD nBufferLength, LPWSTR lpBuffer);
typedef UINT(WINAPI* GetTempFileNameW_t)(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName);
typedef BOOL(WINAPI* QueryServiceStatusEx_t)(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, PBYTE lpData, DWORD cbData);
typedef LSTATUS(WINAPI* RegCloseKey_t)(HKEY hKey);
typedef BOOL(WINAPI* RemoveDirectoryW_t)(LPCWSTR lpPathName);

#define UuidToStringW_SW2_HASH        0x0A907D4E
#define RpcStringFreeW_SW2_HASH       0x0C953D0F
#define RtlImageNtHeader_SW2_HASH     0x00BCFBB5
#define ControlService_SW2_HASH       0x6EC9F5F5
#define Sleep_SW2_HASH                0x1AA40C23
#define GetCurrentDirectoryW_SW2_HASH 0x7495613A
#define SetCurrentDirectoryW_SW2_HASH 0x0E8F3B04
#define CreateFileW_SW2_HASH          0x24976EA4
#define GetFileSize_SW2_HASH          0xF850E4E6
#define StartServiceW_SW2_HASH        0xF9C506E6
#define RegOpenKeyExW_SW2_HASH        0xD9860929
#define RegQueryValueExW_SW2_HASH     0xE31FB5B7
#define GetTempPathW_SW2_HASH         0x7D51ED68
#define GetTempFileNameW_SW2_HASH     0x132B8414
#define QueryServiceStatusEx_SW2_HASH 0x1D84EAF8
#define RegSetValueExW_SW2_HASH       0x1A1D0AD5
#define RegCloseKey_SW2_HASH          0xE6251DA5
#define RemoveDirectoryW_SW2_HASH     0x10D13916

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

typedef struct _OBJECT_NAME_INFORMATION {
  UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#define ObjectNameInformation 1

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
