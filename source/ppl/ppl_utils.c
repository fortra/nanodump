#include "ppl/ppl_utils.h"

BOOL is_win_6_point_3_or_grater(VOID)
{
    PVOID pPeb;
    ULONG32 OSMajorVersion;
    ULONG32 OSMinorVersion;

    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    OSMajorVersion = *RVA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);
    OSMinorVersion = *RVA(PULONG32, pPeb, OSMINORVERSION_OFFSET);

    if (OSMajorVersion > 6)
        return TRUE;

    if (OSMajorVersion < 6)
        return FALSE;

    if (OSMinorVersion >= 3)
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
    name.Length  = (USHORT)wcsnlen(name.Buffer, MAX_PATH);;
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
    name.Length  = (USHORT)wcsnlen(name.Buffer, MAX_PATH);;
    name.Length *= 2;
    name.MaximumLength = name.Length + 2;

    target.Buffer  = targetname;
    target.Length  = (USHORT)wcsnlen(target.Buffer, MAX_PATH);;
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
    name.Length  = (USHORT)wcsnlen(name.Buffer, MAX_PATH);;
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
    FILE_STANDARD_INFORMATION fsi = { 0 };

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
