#pragma once

#include <windows.h>
#include <winternl.h>

#include "dinvoke.h"
#include "syscalls.h"

#ifndef ThreadImpersonationToken
 #define ThreadImpersonationToken 5
#endif

typedef BOOL(WINAPI* ConvertStringSidToSidW_t) (LPCWSTR StringSid, PSID *Sid);
typedef BOOL(WINAPI* CopySid_t) (DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid);
typedef BOOL(WINAPI* ConvertSidToStringSidW_t) (PSID Sid, LPWSTR *StringSid);
typedef BOOL(WINAPI* LookupAccountSidW_t) (LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
typedef BOOL(WINAPI* RevertToSelf_t) (VOID);

#define ConvertStringSidToSidW_SW2_HASH 0x9A0697A4
#define CopySid_SW2_HASH 0xE9DEE47F
#define ConvertSidToStringSidW_SW2_HASH 0x2E89B34F
#define LookupAccountSidW_SW2_HASH 0x093E752B
#define RevertToSelf_SW2_HASH 0x93BC9622

BOOL impersonate_user(
    IN LPCWSTR pwszSid,
    OUT PHANDLE phToken,
    IN LPCWSTR pwszPrivileges[],
    IN DWORD dwPrivilegeCount);

BOOL impersonate(
    IN HANDLE hToken);

BOOL find_process_token_and_duplicate(
    IN LPCWSTR pwszTargetSid,
    IN LPCWSTR pwszPrivileges[],
    IN DWORD dwPrivilegeCount,
    OUT PHANDLE phToken);

BOOL revert_to_self(VOID);

BOOL impersonate_process(
    IN DWORD process_id,
    OUT PHANDLE phProcessToken);

BOOL impersonate_system(
    OUT PHANDLE phSystemToken);

BOOL impersonate_local_service(
    OUT PHANDLE phLocalServiceToken);

BOOL token_get_sid(
    IN HANDLE hToken,
    OUT PSID* ppSid);

BOOL token_get_sid_as_string(
    IN HANDLE hToken,
    OUT LPWSTR* ppwszStringSid);

BOOL is_current_user_system(
    OUT PBOOL pbResult);

BOOL token_compare_sids(
    IN PSID pSidA,
    IN PSID pSidB);

BOOL token_is_not_restricted(
    IN HANDLE hToken,
    OUT PBOOL pbIsNotRestricted);

BOOL token_get_username(
    IN HANDLE hToken,
    OUT LPWSTR* ppwszUsername);
