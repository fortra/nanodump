#include "token_priv.h"
#if defined(NANO) && defined(BOF)
#include "dinvoke.c"
#endif

#if !defined(SSP)

BOOL enable_debug_priv(VOID)
{
    // you can remove this function by providing the compiler flag: -DNODPRIV
    BOOL success = TRUE;
#ifndef NODPRIV
    LPCWSTR ppwszRequiredPrivileges[1] = {
        SeDebugPrivilege
    };

    success = check_token_privileges(
        ppwszRequiredPrivileges,
        1,
        TRUE);
    if (success)
    {
        DPRINT("SeDebugPrivilege enabled");
    }
#endif
    return success;
}

BOOL check_token_privileges(
    IN LPCWSTR ppwszRequiredPrivileges[],
    IN DWORD dwNumRequiredPrivileges,
    IN BOOL bEnablePrivilege)
{
    HANDLE hToken = NULL;
    BOOL success;

    // get a handle to our token
    NTSTATUS status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &hToken);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcessToken", status);
        return FALSE;
    }

    for (int i = 0; i < dwNumRequiredPrivileges; i++)
    {
        // make sure we have all the privileges we need
        success = check_token_privilege(
            hToken,
            ppwszRequiredPrivileges[i],
            bEnablePrivilege);
        if (!success)
        {
            NtClose(hToken); hToken = NULL;
            PRINT_ERR("A privilege is missing: %ls", ppwszRequiredPrivileges[i]);
            return FALSE;
        }
    }

    NtClose(hToken); hToken = NULL;

    return TRUE;
}

BOOL check_token_privilege(
    IN HANDLE hToken,
    IN LPCWSTR pwszPrivilege,
    IN BOOL bEnablePrivilege)
{
    BOOL bReturnValue = FALSE;
    ULONG dwTokenPrivilegesSize = 8, i = 0, dwPrivilegeNameLength = 0;
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    LookupPrivilegeNameW_t LookupPrivilegeNameW;
    LUID_AND_ATTRIBUTES laa = { 0 };
    TOKEN_PRIVILEGES tkp = { 0 };
    LPWSTR pwszPrivilegeNameTemp;
    NTSTATUS status;
    BOOL success;

    LookupPrivilegeNameW = (LookupPrivilegeNameW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        LookupPrivilegeNameW_SW2_HASH,
        0);
    if (!LookupPrivilegeNameW)
    {
        DPRINT_ERR("Address of 'LookupPrivilegeNameW' not found");
        goto end;
    }

    do
    {
        pTokenPrivileges = intAlloc(dwTokenPrivilegesSize);
        if (!pTokenPrivileges)
        {
            malloc_failed();
            goto end;
        }

        status = NtQueryInformationToken(
            hToken,
            TokenPrivileges,
            pTokenPrivileges,
            dwTokenPrivilegesSize,
            &dwTokenPrivilegesSize);
        if (NT_SUCCESS(status))
            break;

        intFree(pTokenPrivileges); pTokenPrivileges = NULL;
    } while (status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationToken", status);
        goto end;
    }

    for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
    {
        laa = pTokenPrivileges->Privileges[i];
        dwPrivilegeNameLength = 0;

        success = LookupPrivilegeNameW(
            NULL,
            &laa.Luid,
            NULL,
            &dwPrivilegeNameLength);
        if (success || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            function_failed("LookupPrivilegeNameW");
            goto end;
        }
        dwPrivilegeNameLength++;

        pwszPrivilegeNameTemp = intAlloc(dwPrivilegeNameLength * sizeof(WCHAR));
        if (!pwszPrivilegeNameTemp)
        {
            malloc_failed();
            goto end;
        }

        success = LookupPrivilegeNameW(
            NULL,
            &laa.Luid,
            pwszPrivilegeNameTemp,
            &dwPrivilegeNameLength);
        if (!success)
        {
            function_failed("LookupPrivilegeNameW");
            goto end;
        }

        if (!_wcsicmp(pwszPrivilegeNameTemp, pwszPrivilege))
        {
            // found it
            if (bEnablePrivilege)
            {
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Luid = laa.Luid;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                status = NtAdjustPrivilegesToken(
                    hToken,
                    FALSE,
                    &tkp,
                    sizeof(TOKEN_PRIVILEGES),
                    NULL,
                    NULL);
                if (!NT_SUCCESS(status))
                {
                    syscall_failed("NtAdjustPrivilegesToken", status);
                    goto end;
                }
            }
            bReturnValue = TRUE;
            break;
        }
        intFree(pwszPrivilegeNameTemp); pwszPrivilegeNameTemp = NULL;
    }

    if (!bReturnValue)
    {
        DPRINT_ERR("The privilege %ls was not found", pwszPrivilege);
    }

end:
    if (pTokenPrivileges)
        intFree(pTokenPrivileges);
    if (pwszPrivilegeNameTemp)
        intFree(pwszPrivilegeNameTemp);

    return bReturnValue;
}

#endif
