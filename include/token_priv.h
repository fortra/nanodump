#pragma once

#include <windows.h>
#include <winternl.h>

#include "utils.h"
#include "dinvoke.h"

typedef BOOL(WINAPI* LookupPrivilegeValueW_t) (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
typedef BOOL(WINAPI* LookupPrivilegeNameW_t) (LPCSTR lpSystemName, PLUID lpLuid, LPWSTR lpName, LPDWORD cchName);

#define LookupPrivilegeValueW_SW2_HASH 0xD496970C
#define LookupPrivilegeNameW_SW2_HASH 0x11A5C11E

#define SeDebugPrivilege L"SeDebugPrivilege"

BOOL enable_impersonate_priv(VOID);

BOOL enable_debug_priv(VOID);

BOOL check_token_privileges(
    IN HANDLE hToken OPTIONAL,
    IN LPCWSTR ppwszRequiredPrivileges[],
    IN ULONG32 dwNumRequiredPrivileges,
    IN BOOL bEnablePrivilege);

BOOL check_token_privilege(
    IN HANDLE hToken OPTIONAL,
    IN LPCWSTR pwszPrivilege,
    IN BOOL bEnablePrivilege);
