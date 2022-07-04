#include "impersonate.h"


BOOL impersonate_user(
    IN LPCWSTR pwszSid,
    OUT PHANDLE phToken,
    IN LPCWSTR pwszPrivileges[],
    IN DWORD dwPrivilegeCount)
{
    BOOL bReturnValue = FALSE;
    *phToken = NULL;
    HANDLE hToken = NULL;
    BOOL success = FALSE;

    LPCWSTR ppwszRequiredPrivileges[2] = {
        L"SeDebugPrivilege",
        L"SeImpersonatePrivilege"
    };

    success = check_token_privileges(
        NULL,
        ppwszRequiredPrivileges,
        ARRAY_SIZE(ppwszRequiredPrivileges),
        TRUE);
    if (!success)
        goto end;

    success = find_process_token_and_duplicate(
        pwszSid,
        pwszPrivileges,
        dwPrivilegeCount,
        &hToken);
    if (!success)
        goto end;

    success = impersonate(hToken);
    if (!success)
        goto end;

    *phToken = hToken;
    bReturnValue = TRUE;

end:
    if (!bReturnValue && hToken)
        NtClose(hToken);

    return bReturnValue;
}

BOOL impersonate(
    IN HANDLE hToken)
{
    NTSTATUS status;

    status = NtSetInformationThread(
        NtCurrentThread(),
        ThreadImpersonationToken,
        &hToken,
        sizeof(HANDLE));
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetInformationThread", status);
        return FALSE;
    }

    return TRUE;
}

BOOL find_process_token_and_duplicate(
    IN LPCWSTR pwszTargetSid,
    IN LPCWSTR pwszPrivileges[],
    IN DWORD dwPrivilegeCount,
    OUT PHANDLE phToken)
{
    BOOL bReturnValue = FALSE;

    PSID pTargetSid = NULL;
    PVOID pBuffer = NULL;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    HANDLE hProcess = NULL, hToken = NULL, hTokenDup = NULL;
    DWORD dwBufSize = 0x1000;
    PSID pSidTmp = NULL;
    LPWSTR pwszUsername = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ConvertStringSidToSidW_t ConvertStringSidToSidW;
    CLIENT_ID uPid = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    OBJECT_ATTRIBUTES TokenObjectAttributes = { 0 };
    SECURITY_QUALITY_OF_SERVICE Qos = { 0 };
    BOOL success;

    ConvertStringSidToSidW = (ConvertStringSidToSidW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ConvertStringSidToSidW_SW2_HASH,
        0);
    if (!ConvertStringSidToSidW)
    {
        api_not_found("ConvertStringSidToSidW");
        goto end;
    }

    success = ConvertStringSidToSidW(pwszTargetSid, &pTargetSid);
    if (!success)
    {
        function_failed("ConvertStringSidToSidW");
        goto end;
    }

    // get information of all currently running processes
    do
    {
        pBuffer = intAlloc(dwBufSize);
        if (!pBuffer)
        {
            malloc_failed();
            goto end;
        }

        status = NtQuerySystemInformation(
            SystemProcessInformation,
            pBuffer,
            dwBufSize,
            &dwBufSize);

        if (NT_SUCCESS(status))
            break;

        intFree(pBuffer); pBuffer = NULL;
    } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQuerySystemInformation", status);
        goto end;
    }

    pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    InitializeObjectAttributes(&TokenObjectAttributes, NULL, 0, NULL, NULL);
    Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = 0;
    Qos.EffectiveOnly = FALSE;
    TokenObjectAttributes.SecurityQualityOfService = &Qos;

    while (TRUE)
    {
        uPid.UniqueProcess = pProcInfo->UniqueProcessId;

        status = NtOpenProcess(
            &hProcess,
            PROCESS_QUERY_INFORMATION,
            &ObjectAttributes,
            &uPid);
        if (NT_SUCCESS(status))
        {
            // open a handle to the token of the process
            status = NtOpenProcessToken(
                hProcess,
                TOKEN_QUERY|TOKEN_DUPLICATE,
                &hToken);

            if (NT_SUCCESS(status))
            {
                status = NtDuplicateToken(
                    hToken,
                    MAXIMUM_ALLOWED,
                    &TokenObjectAttributes,
                    FALSE,
                    TokenImpersonation,
                    &hTokenDup);

                if (NT_SUCCESS(status))
                {
                    success = token_get_sid(hTokenDup, &pSidTmp);
                    if (success)
                    {
                        success = token_get_username(hTokenDup, &pwszUsername);
                        if (success)
                        {
                            success = token_compare_sids(pSidTmp, pTargetSid);
                            if (success)
                            {
                                DPRINT("Found a potential Process candidate: PID=%d - Image='%ls' - User='%ls'", (USHORT)(ULONG_PTR)pProcInfo->UniqueProcessId, pProcInfo->ImageName.Buffer, pwszUsername);

                                BOOL bTokenIsNotRestricted = FALSE;
                                success = token_is_not_restricted(hTokenDup, &bTokenIsNotRestricted);
                                if (success)
                                {
                                    if (!bTokenIsNotRestricted)
                                    {
                                        DPRINT("This token is restricted.");
                                    }
                                    else
                                    {
                                        DPRINT("This token is not restricted.");

                                        success = check_token_privileges(
                                            hTokenDup,
                                            pwszPrivileges,
                                            dwPrivilegeCount,
                                            TRUE);
                                        if (success)
                                        {
                                            DPRINT("Found a valid Token.");
                                            *phToken = hTokenDup;
                                            bReturnValue = TRUE;
                                        }
                                        else
                                        {
                                            DPRINT("The token was not valid.");
                                        }
                                    }
                                }
                            }
                            intFree(pwszUsername); pwszUsername = NULL;
                        }
                        LocalFree(pSidTmp); pSidTmp = NULL;
                    }
                    if (!bReturnValue)
                    {
                        NtClose(hTokenDup); hTokenDup = NULL;
                    }
                }
                NtClose(hToken); hToken = NULL;
            }
            NtClose(hProcess); hProcess = NULL;
        }
        // If we found a valid token, stop
        if (bReturnValue)
            break;

        // If next entry is null, stop
        if (!pProcInfo->NextEntryOffset)
            break;

        // Increment SYSTEM_PROCESS_INFORMATION pointer
        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
    }

    if (!bReturnValue)
    {
        PRINT_ERR("No valid process token to impersonate was found.");
    }

end:
    if (pTargetSid)
        LocalFree(pTargetSid);
    if (pBuffer)
        intFree(pBuffer);

    return bReturnValue;
}

BOOL revert_to_self(VOID)
{
    BOOL success = FALSE;
    RevertToSelf_t RevertToSelf = NULL;

    RevertToSelf = (RevertToSelf_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RevertToSelf_SW2_HASH,
        0);
    if (!RevertToSelf)
    {
        api_not_found("RevertToSelf");
        return FALSE;
    }

    success = RevertToSelf();

    if (success)
    {
        DPRINT("Reverted to self");
    }
    else
    {
        function_failed("RevertToSelf");
    }

    return success;
}

BOOL impersonate_process(
    IN DWORD process_id,
    OUT PHANDLE phProcessToken)
{
    BOOL success = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hTokenDup = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    CLIENT_ID uPid = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    SECURITY_QUALITY_OF_SERVICE Qos = { 0 };
    OBJECT_ATTRIBUTES TokenObjectAttributes = { 0 };
    *phProcessToken = NULL;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    InitializeObjectAttributes(&TokenObjectAttributes, NULL, 0, NULL, NULL);
    Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = 0;
    Qos.EffectiveOnly = FALSE;
    TokenObjectAttributes.SecurityQualityOfService = &Qos;

    uPid.UniqueProcess = (HANDLE)(ULONG_PTR)process_id;

    LPCWSTR ppwszRequiredPrivileges[2] = {
        L"SeDebugPrivilege",
        L"SeImpersonatePrivilege"
    };

    success = check_token_privileges(
        NULL,
        ppwszRequiredPrivileges,
        ARRAY_SIZE(ppwszRequiredPrivileges),
        TRUE);
    if (!success)
        goto end;

    status = NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_INFORMATION,
        &ObjectAttributes,
        &uPid);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcess", status);
        goto end;
    }

    status = NtOpenProcessToken(
        hProcess,
        TOKEN_QUERY|TOKEN_DUPLICATE,
        &hToken);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcessToken", status);
        goto end;
    }

    status = NtDuplicateToken(
        hToken,
        MAXIMUM_ALLOWED,
        &TokenObjectAttributes,
        FALSE,
        TokenImpersonation,
        &hTokenDup);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtDuplicateToken", status);
        goto end;
    }

    success = impersonate(hTokenDup);
    if (!success)
        goto end;

    *phProcessToken = hTokenDup;
    DPRINT("Impersonating PID %ld", process_id);

end:
    if (hProcess)
        NtClose(hProcess);
    if (hToken)
        NtClose(hToken);
    if (!success && hTokenDup)
        NtClose(hTokenDup);

    return success;
}

BOOL impersonate_system(
    OUT PHANDLE phSystemToken)
{
    BOOL success;
    LPCWSTR pwszPrivileges[2] = {
        L"SeDebugPrivilege",
        L"SeAssignPrimaryTokenPrivilege"
    };

    success = impersonate_user(
        L"S-1-5-18",
        phSystemToken,
        pwszPrivileges,
        ARRAY_SIZE(pwszPrivileges));

    if (!success)
    {
        PRINT_ERR("Could not impersonate SYSTEM");
    }

    return success;
}

BOOL impersonate_local_service(
    OUT PHANDLE phLocalServiceToken)
{
    BOOL success;
    
    success = impersonate_user(
        L"S-1-5-19",
        phLocalServiceToken,
        NULL,
        0);

    if (!success)
    {
        PRINT_ERR("Could not impersonate LOCAL SERVICE");
    }

    return success;
}

BOOL token_get_sid(
    IN HANDLE hToken,
    OUT PSID* ppSid)
{
    BOOL bReturnValue = FALSE;
    DWORD dwSize = 8;
    PTOKEN_USER pTokenUser = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL success;
    CopySid_t CopySid;

    CopySid = (CopySid_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CopySid_SW2_HASH,
        0);
    if (!CopySid)
    {
        api_not_found("CopySid");
        goto end;
    }

    do
    {
        pTokenUser = intAlloc(dwSize);
        if (!pTokenUser)
        {
            malloc_failed();
            goto end;
        }

        status = NtQueryInformationToken(
            hToken,
            TokenUser,
            pTokenUser,
            dwSize,
            &dwSize);
        if (NT_SUCCESS(status))
            break;

        intFree(pTokenUser); pTokenUser = NULL;
    } while (status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationToken", status);
        goto end;
    }

    *ppSid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
    if (!*ppSid)
    {
        function_failed("LocalAlloc");
        goto end;
    }

    success = CopySid(
        SECURITY_MAX_SID_SIZE,
        *ppSid,
        pTokenUser->User.Sid);
    if (!success)
    {
        function_failed("CopySid");
        goto end;
    }

    bReturnValue = TRUE;

end:
    if (pTokenUser)
        intFree(pTokenUser);
    if (!bReturnValue && *ppSid)
    {
        LocalFree(*ppSid); *ppSid = NULL;
    }

    return bReturnValue;
}

BOOL token_get_sid_as_string(
    IN HANDLE hToken,
    OUT LPWSTR* ppwszStringSid)
{
    PSID pSid = NULL;
    BOOL success;
    ConvertSidToStringSidW_t ConvertSidToStringSidW;

    ConvertSidToStringSidW = (ConvertSidToStringSidW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ConvertSidToStringSidW_SW2_HASH,
        0);
    if (!ConvertSidToStringSidW)
    {
        api_not_found("ConvertSidToStringSidW");
        return FALSE;
    }

    success = token_get_sid(hToken, &pSid);
    if (!success)
        return FALSE;

    success = ConvertSidToStringSidW(pSid, ppwszStringSid);

    LocalFree(pSid); pSid = NULL;

    if (!success)
    {
        function_failed("ConvertSidToStringSidW");
        return FALSE;
    }

    return TRUE;
}

BOOL is_current_user_system(
    OUT PBOOL pbResult)
{
    HANDLE hToken = NULL;
    LPWSTR pwszStringSid = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL success;

    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &hToken);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcessToken", status);
        return FALSE;
    }

    success = token_get_sid_as_string(
        hToken,
        &pwszStringSid);

    NtClose(hToken); hToken = NULL;

    if (!success)
        return FALSE;

    *pbResult = _wcsicmp(pwszStringSid, L"S-1-5-18") == 0;

    LocalFree(pwszStringSid); pwszStringSid = NULL;

    return TRUE;
}

BOOL token_compare_sids(
    IN PSID pSidA,
    IN PSID pSidB)
{
    BOOL bReturnValue = FALSE;
    LPWSTR pwszSidA = NULL;
    LPWSTR pwszSidB = NULL;
    ConvertSidToStringSidW_t ConvertSidToStringSidW;
    BOOL success;

    ConvertSidToStringSidW = (ConvertSidToStringSidW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ConvertSidToStringSidW_SW2_HASH,
        0);
    if (!ConvertSidToStringSidW)
    {
        api_not_found("ConvertSidToStringSidW");
        goto end;
    }

    success = ConvertSidToStringSidW(pSidA, &pwszSidA);
    if (!success)
    {
        function_failed("ConvertSidToStringSidW");
        goto end;
    }

    success = ConvertSidToStringSidW(pSidB, &pwszSidB);
    if (!success)
    {
        function_failed("ConvertSidToStringSidW");
        goto end;
    }

    bReturnValue = _wcsicmp(pwszSidA, pwszSidB) == 0;

end:
    if (pwszSidA)
        LocalFree(pwszSidA);
    if (pwszSidB)
        LocalFree(pwszSidB);

    return bReturnValue;
}

BOOL token_is_not_restricted(
    IN HANDLE hToken,
    OUT PBOOL pbIsNotRestricted)
{
    DWORD dwSize = 8;
    PTOKEN_GROUPS pTokenGroups = NULL;
    NTSTATUS status;

    do
    {
        pTokenGroups = intAlloc(dwSize);
        if (!pTokenGroups)
        {
            malloc_failed();
            return FALSE;
        }

        status = NtQueryInformationToken(
            hToken,
            TokenRestrictedSids,
            pTokenGroups,
            dwSize,
            &dwSize);
        if (NT_SUCCESS(status))
            break;

        intFree(pTokenGroups); pTokenGroups = NULL;
    } while (status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationToken", status);
        return FALSE;
    }

    *pbIsNotRestricted = pTokenGroups->GroupCount == 0;

    intFree(pTokenGroups); pTokenGroups = NULL;

    return TRUE;
}

BOOL token_get_username(
    IN HANDLE hToken,
    OUT LPWSTR* ppwszUsername)
{
    BOOL bReturnValue = FALSE;
    PSID pSid = NULL;
    const DWORD dwMaxSize = 256;
    WCHAR wszUsername[256] = { 0 };
    WCHAR wszDomain[256] = { 0 };
    DWORD dwMaxUsername = dwMaxSize;
    DWORD dwMaxDomain = dwMaxSize;
    SID_NAME_USE type;
    BOOL success;
    LookupAccountSidW_t LookupAccountSidW;

    LookupAccountSidW = (LookupAccountSidW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        LookupAccountSidW_SW2_HASH,
        0);
    if (!LookupAccountSidW)
    {
        api_not_found("LookupAccountSidW");
        goto end;
    }

    success = token_get_sid(hToken, &pSid);
    if (!success)
        goto end;

    success = LookupAccountSidW(
        NULL,
        pSid,
        wszUsername,
        &dwMaxUsername,
        wszDomain,
        &dwMaxDomain,
        &type);
    if (!success)
    {
        function_failed("LookupAccountSidW");
        goto end;
    }

    *ppwszUsername = intAlloc((dwMaxSize * 2 + 1) * sizeof(WCHAR));
    if (!*ppwszUsername)
    {
        malloc_failed();
        goto end;
    }

    wcsncpy(*ppwszUsername, wszDomain, dwMaxSize * 2 + 1);
    wcsncat(*ppwszUsername, L"\\", dwMaxSize * 2 + 1);
    wcsncat(*ppwszUsername, wszUsername, dwMaxSize * 2 + 1);

    bReturnValue = TRUE;

end:
    if (pSid)
        LocalFree(pSid);

    return bReturnValue;
}
