#pragma once

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

void free_linked_list(PVOID head);
PVOID allocate_memory(PSIZE_T RegionSize);
void erase_dump_from_memory(PVOID BaseAddress, SIZE_T RegionSize);
void generate_invalid_sig(PULONG32 Signature, PSHORT Version, PSHORT ImplementationVersion);
