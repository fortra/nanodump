#pragma once

#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#include <sspi.h>

#include "dinvoke.h"
#include "nanodump.h"
#include "output.h"
#if PASS_PARAMS_VIA_NAMED_PIPES == 1
#include "pipe.h"
#endif

typedef NTSTATUS(WINAPI* AddSecurityPackageW_t) (LPWSTR pszPackageName, PSECURITY_PACKAGE_OPTIONS pOptions);
typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

#define AddSecurityPackageW_SW2_HASH 0x09B08696
#define CreateThread_SW2_HASH        0x2C912627

#define SSPICLI_DLL L"SSPICLI.DLL"

DWORD WINAPI load_ssp(LPVOID Parameter);
