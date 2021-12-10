#pragma once

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

BOOL wait_for_process(HANDLE hProcess);
BOOL delete_file(LPCSTR filepath);
BOOL file_exists(LPCSTR filepath);
DWORD get_lsass_pid(void);
void print_success(LPCSTR dump_name, BOOL use_valid_sig, BOOL do_write);
void free_linked_list(PVOID head);
PVOID allocate_memory(PSIZE_T RegionSize);
void encrypt_dump(Pdump_context dc);
void erase_dump_from_memory(Pdump_context dc);
void generate_invalid_sig(PULONG32 Signature, PSHORT Version, PSHORT ImplementationVersion);
