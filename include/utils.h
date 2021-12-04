#pragma once

void free_linked_list(PVOID head);
PVOID allocate_memory(PSIZE_T RegionSize);
void erase_dump_from_memory(PVOID BaseAddress, SIZE_T RegionSize);
void generate_invalid_sig(PULONG32 Signature, PSHORT Version, PSHORT ImplementationVersion);
