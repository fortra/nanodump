#pragma once

#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <ntsecpkg.h>
#include <ntsecpkg.h>

typedef NTSTATUS(WINAPI* AddSecurityPackageA_t) (LPSTR pszPackageName, PSECURITY_PACKAGE_OPTIONS pOptions);

#define AddSecurityPackageA_SW2_HASH 0x09B0AC5A

#define SSPICLI_DLL L"SSPICLI.DLL"

//#define SEC_E_SECPKG_NOT_FOUND 0x80090305

void load_ssp(LPSTR ssp_path);
