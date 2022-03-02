#include "ppl/ppl_utils.h"

BOOL token_get_sid(
    IN HANDLE hToken,
    OUT PSID* ppSid)
{
    DWORD dwSize = 8;
    PTOKEN_USER pTokenUser = NULL;
    NTSTATUS status;
    BOOL success;
    CopySid_t CopySid;

    CopySid = (CopySid_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CopySid_SW2_HASH,
        0);
    if (!CopySid)
    {
        DPRINT_ERR("Address of 'CopySid' not found");
        return FALSE;
    }

    do
    {
        pTokenUser = intAlloc(dwSize);
        if (!pTokenUser)
        {
            malloc_failed();
            return FALSE;
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
        return FALSE;
    }

    *ppSid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
    if (!*ppSid)
    {
        function_failed("LocalAlloc");
        return FALSE;
    }

    success = CopySid(
        SECURITY_MAX_SID_SIZE,
        *ppSid,
        pTokenUser->User.Sid);
    if (!success)
    {
        function_failed("CopySid");
        LocalFree(*ppSid); *ppSid = NULL;
        return FALSE;
    }

    return TRUE;
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
        DPRINT_ERR("Address of 'ConvertSidToStringSidW' not found");
        return FALSE;
    }

    success = token_get_sid(hToken, &pSid);
    if (!success)
        return FALSE;

    success = ConvertSidToStringSidW(pSid, ppwszStringSid);
    if (!success)
    {
        function_failed("ConvertSidToStringSidW");
        LocalFree(pSid); pSid = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL is_current_user_system(
    OUT PBOOL pbResult)
{
    HANDLE hToken = NULL;
    LPWSTR pwszStringSid = NULL;
    NTSTATUS status;
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
        DPRINT_ERR("Address of 'ConvertSidToStringSidW' not found");
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
        DPRINT_ERR("Address of 'LookupAccountSidW' not found");
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

BOOL is_win_8_point_1_or_grater(VOID)
{
    PVOID pPeb;
    ULONG32 OSMajorVersion;
    ULONG32 OSMinorVersion;

    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    OSMajorVersion = *RVA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);
    OSMinorVersion = *RVA(PULONG32, pPeb, OSMINORVERSION_OFFSET);

    if (OSMajorVersion > 8)
        return TRUE;

    if (OSMajorVersion < 8)
        return FALSE;

    if (OSMinorVersion >= 1)
        return TRUE;

    return FALSE;
}

BOOL is_win_10_or_grater(VOID)
{
    PVOID pPeb;
    ULONG32 OSMajorVersion;

    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    OSMajorVersion = *RVA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);

    if (OSMajorVersion >= 10)
        return TRUE;

    return FALSE;
}

BOOL object_manager_create_directory(
    IN LPWSTR dirname,
    OUT PHANDLE phDirectory)
{
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };
    NTSTATUS status = 0;

    *phDirectory = NULL;

    name.Buffer  = dirname;
    name.Length  = wcsnlen(name.Buffer, MAX_PATH);;
    name.Length *= 2;
    name.MaximumLength = name.Length + 2;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateDirectoryObjectEx(
        phDirectory,
        DIRECTORY_ALL_ACCESS,
        &oa,
        NULL,
        FALSE);
    // if we get STATUS_OBJECT_NAME_COLLISION, assume is already created
    if (status != STATUS_OBJECT_NAME_COLLISION && !NT_SUCCESS(status))
    {
        syscall_failed("NtCreateDirectoryObjectEx", status);
        return FALSE;
    }

    return TRUE;
}

BOOL object_manager_create_symlik(
    IN LPWSTR linkname,
    IN LPWSTR targetname,
    OUT PHANDLE phLink)
{
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };
    UNICODE_STRING target = { 0 };
    NTSTATUS status;

    *phLink = NULL;

    name.Buffer  = linkname;
    name.Length  = wcsnlen(name.Buffer, MAX_PATH);;
    name.Length *= 2;
    name.MaximumLength = name.Length + 2;

    target.Buffer  = targetname;
    target.Length  = wcsnlen(target.Buffer, MAX_PATH);;
    target.Length *= 2;
    target.MaximumLength = target.Length + 2;

    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateSymbolicLinkObject(
        phLink,
        SYMBOLIC_LINK_ALL_ACCESS,
        &oa,
        &target);
    // if we get STATUS_OBJECT_NAME_COLLISION, assume is already created
    if (status != STATUS_OBJECT_NAME_COLLISION && !NT_SUCCESS(status))
    {
        syscall_failed("NtCreateSymbolicLinkObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL check_known_dll_symbolic_link(
    IN LPCWSTR pwszDllName,
    IN LPWSTR pwszTarget)
{
    BOOL bReturnValue = FALSE;
    NTSTATUS status = 0;
    LPWSTR pwszLinkName = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };
    UNICODE_STRING target = { 0 };
    LPWSTR pwszTargetLocal = NULL;
    HANDLE hLink = NULL;
    ULONG length = 0;

    pwszLinkName = intAlloc(MAX_PATH * sizeof(WCHAR));
    if (!pwszLinkName)
    {
        malloc_failed();
        goto end;
    }

    pwszTargetLocal = intAlloc(MAX_PATH * sizeof(WCHAR));
    if (!pwszTargetLocal)
    {
        malloc_failed();
        goto end;
    }

    wcsncpy(pwszLinkName, L"\\KnownDlls\\", MAX_PATH);
    wcsncat(pwszLinkName, pwszDllName, MAX_PATH);

    name.Buffer  = pwszLinkName;
    name.Length  = wcsnlen(name.Buffer, MAX_PATH);;
    name.Length *= 2;
    name.MaximumLength = name.Length + 2;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenSymbolicLinkObject(
        &hLink,
        SYMBOLIC_LINK_QUERY,
        &oa);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenSymbolicLinkObject", status);
        goto end;
    }

    target.Buffer = pwszTargetLocal;
    target.Length = 0;
    target.MaximumLength = MAX_PATH * sizeof(WCHAR);

    status = NtQuerySymbolicLinkObject(
        hLink,
        &target,
        &length);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQuerySymbolicLinkObject", status);
        goto end;
    }

    bReturnValue = _wcsicmp(target.Buffer, pwszTarget) == 0;

end:
    if (pwszLinkName)
        intFree(pwszLinkName);
    if (pwszTargetLocal)
        intFree(pwszTargetLocal);
    if (hLink)
        NtClose(hLink);

    return bReturnValue;
}

BOOL get_file_size(
    IN HANDLE hFile,
    OUT PDWORD file_size)
{
    NTSTATUS status;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION fsi;

    if (!hFile)
        return FALSE;

    status = NtQueryInformationFile(
        hFile,
        &IoStatusBlock,
        &fsi,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationFile", status);
        return FALSE;
    }

    // TODO: get the full QuadPart?
    *file_size = fsi.AllocationSize.LowPart;

    return TRUE;
}
