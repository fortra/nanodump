#pragma once

typedef BOOL(WINAPI* LOOKUPPRIVILEGEVALUEW) (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

#define ADVAPI32 "Advapi32.dll"
#define LookupPrivilegeValueW_SW2_HASH 0xD496970C

#define SeDebugPrivilege L"SeDebugPrivilege"

BOOL enable_debug_priv(void);
