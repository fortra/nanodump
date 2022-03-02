#pragma once

#include <windows.h>
#include <winternl.h>

#include "nanodump.h"
#include "dinvoke.h"

typedef BOOL(WINAPI* SetKernelObjectSecurity_t) (HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);
typedef BOOL(WINAPI* InitializeSecurityDescriptor_t) (PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
typedef BOOL(WINAPI* SetSecurityDescriptorDacl_t) (PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted);

#define SetKernelObjectSecurity_SW2_HASH 0x06AE0E20
#define InitializeSecurityDescriptor_SW2_HASH 0x0388211D
#define SetSecurityDescriptorDacl_SW2_HASH 0x7BDD4356

BOOL get_current_dll_filename(
	OUT LPCWSTR* ppwszDllName);

BOOL delete_known_dll_entry(VOID);
