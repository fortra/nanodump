#include "token_priv.h"
#if defined(NANO) && defined(BOF)
#include "dinvoke.c"
#endif

#if !defined(SSP)

BOOL enable_impersonate_priv(VOID)
{
    BOOL success = check_token_privilege(
        NULL,
        L"SeImpersonatePrivilege",
        TRUE);
    if (!success)
    {
        PRINT_ERR("Could not enable SeImpersonatePrivilege. Are you elevated?");
    }
    return success;
}

BOOL enable_debug_priv(VOID)
{
    BOOL success = check_token_privilege(
        NULL,
        SeDebugPrivilege,
        TRUE);
    if (!success)
    {
        PRINT_ERR("Could not enable SeDebugPrivilege. Are you elevated?");
    }
    return success;
}

BOOL check_token_privileges(
    IN HANDLE hToken OPTIONAL,
    IN LPCWSTR ppwszRequiredPrivileges[],
    IN ULONG32 dwNumRequiredPrivileges,
    IN BOOL bEnablePrivilege)
{
    BOOL success = FALSE;
    BOOL own_token = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!ppwszRequiredPrivileges || !dwNumRequiredPrivileges)
        return TRUE;

    if (!hToken)
    {
        // get a handle to our token
        own_token = TRUE;
        status = NtOpenProcessToken(
            NtCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &hToken);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtOpenProcessToken", status);
            goto end;
        }
    }

    for (ULONG32 i = 0; i < dwNumRequiredPrivileges; i++)
    {
        // make sure we have all the privileges we need
        success = check_token_privilege(
            hToken,
            ppwszRequiredPrivileges[i],
            bEnablePrivilege);
        if (!success && own_token && bEnablePrivilege)
        {
            PRINT_ERR("A privilege is missing: %ls. Are you elevated?", ppwszRequiredPrivileges[i]);
            goto end;
        }
        else if (!success)
        {
            PRINT_ERR("A privilege is missing: %ls", ppwszRequiredPrivileges[i]);
            goto end;
        }
    }

    success = TRUE;

end:
    if (own_token && hToken)
        NtClose(hToken);

    return success;
}

BOOL check_token_privilege(
    IN HANDLE hToken OPTIONAL,
    IN LPCWSTR pwszPrivilege,
    IN BOOL bEnablePrivilege)
{
    BOOL bReturnValue = FALSE;
    ULONG dwTokenPrivilegesSize = 8, i = 0, dwPrivilegeNameLength = 0;
    ULONG dwPrevTokenPrivilegesSize = dwTokenPrivilegesSize;
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    LookupPrivilegeNameW_t LookupPrivilegeNameW;
    LUID_AND_ATTRIBUTES laa = { 0 };
    TOKEN_PRIVILEGES tkp = { 0 };
    PRIVILEGE_SET priv_set = { 0 };
    LPWSTR pwszPrivilegeNameTemp = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL own_token = FALSE;
    BOOL success = FALSE;
    BOOL found_priv = FALSE;

    LookupPrivilegeNameW = (LookupPrivilegeNameW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        LookupPrivilegeNameW_SW2_HASH,
        0);
    if (!LookupPrivilegeNameW)
    {
        api_not_found("LookupPrivilegeNameW");
        goto end;
    }

    if (!hToken)
    {
        // get a handle to our token
        own_token = TRUE;
        status = NtOpenProcessToken(
            NtCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &hToken);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtOpenProcessToken", status);
            goto end;
        }
    }

    do
    {
        dwPrevTokenPrivilegesSize = dwTokenPrivilegesSize;
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

        DATA_FREE(pTokenPrivileges, dwPrevTokenPrivilegesSize);
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
            found_priv = TRUE;

            // test if already enabled
            priv_set.PrivilegeCount = 1;
            priv_set.Privilege[0].Luid = laa.Luid;
            priv_set.Privilege[0].Attributes = laa.Attributes;
            status = NtPrivilegeCheck(
                hToken,
                &priv_set,
                &bReturnValue);
            if (!NT_SUCCESS(status))
            {
                syscall_failed("NtPrivilegeCheck", status);
                bReturnValue = FALSE;
                goto end;
            }

            if (bReturnValue)
            {
                DPRINT("Privilege %ls was already enabled", pwszPrivilegeNameTemp);
            }

            if (!bReturnValue && bEnablePrivilege)
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
                DPRINT("Enabled %ls", pwszPrivilegeNameTemp);
                bReturnValue = TRUE;
            }

            if (!bReturnValue && !bEnablePrivilege)
            {
                DPRINT("The privilege %ls is not enabled", pwszPrivilegeNameTemp);
            }

            break;
        }
        DATA_FREE(pwszPrivilegeNameTemp, wcslen(pwszPrivilegeNameTemp) * sizeof(WCHAR));
    }

    if (!found_priv)
    {
        DPRINT_ERR("The privilege %ls was not found", pwszPrivilege);
    }

end:
    if (pTokenPrivileges)
    {
        DATA_FREE(pTokenPrivileges, dwTokenPrivilegesSize);
    }
    if (pwszPrivilegeNameTemp)
    {
        DATA_FREE(pwszPrivilegeNameTemp, wcslen(pwszPrivilegeNameTemp) * sizeof(WCHAR));
    }
    if (own_token && hToken)
        NtClose(hToken);

    return bReturnValue;
}

#endif
