#pragma once

#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#include <sspi.h>

#include "dinvoke.h"
#include "nanodump.h"
#include "output.h"

typedef NTSTATUS(WINAPI* AddSecurityPackageW_t) (LPWSTR pszPackageName, PSECURITY_PACKAGE_OPTIONS pOptions);

#define AddSecurityPackageW_SW2_HASH 0x09B08696

#define SSPICLI_DLL L"SSPICLI.DLL"

//#define SEC_E_SECPKG_NOT_FOUND 0x80090305

VOID load_ssp(
    IN LPSTR ssp_path);
