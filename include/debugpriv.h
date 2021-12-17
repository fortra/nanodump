#pragma once

typedef BOOL(WINAPI* LookupPrivilegeValueW_t) (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

#define LookupPrivilegeValueW_SW2_HASH 0xD496970C

#define SeDebugPrivilege L"SeDebugPrivilege"

BOOL enable_debug_priv(void);
