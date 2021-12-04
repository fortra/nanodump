#pragma once

#include <windows.h>
#include <winternl.h>

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* LOOKUPPRIVILEGEVALUEW) (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

BOOL enable_debug_priv(void);
