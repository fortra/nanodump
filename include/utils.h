#pragma once

#include "nanodump.h"
#include "ntdefs.h"
#include "output.h"

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define RVA(type, base_addr, rva) (type)(ULONG_PTR)((ULONG_PTR) base_addr + rva)

#ifdef _WIN64
 #define CID_OFFSET 0x40
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define CID_OFFSET 0x20
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

BOOL kill_process(DWORD pid, HANDLE hProcess);
BOOL is_lsass(HANDLE hProcess);
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
void encrypt_dump(PVOID base_address, SIZE_T region_size);
void erase_dump_from_memory(PVOID base_address, SIZE_T region_size);
void generate_invalid_sig(PULONG32 Signature, PUSHORT Version, PUSHORT ImplementationVersion);
BOOL create_file(PUNICODE_STRING full_dump_path);
BOOL write_file(PUNICODE_STRING full_dump_path, PBYTE fileData, ULONG32 fileLength);
BOOL remove_syscall_callback_hook(VOID);
#ifdef BOF
BOOL download_file(LPCSTR fileName, char fileData[], ULONG32 fileLength);
#endif

typedef enum  {
  PSS_CAPTURE_NONE = 0x00000000,
  PSS_CAPTURE_VA_CLONE = 0x00000001,
  PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
  PSS_CAPTURE_HANDLES = 0x00000004,
  PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
  PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
  PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
  PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
  PSS_CAPTURE_THREADS = 0x00000080,
  PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
  PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
  PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
  PSS_CAPTURE_VA_SPACE = 0x00000800,
  PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
  PSS_CAPTURE_IPT_TRACE = 0x00002000,
  PSS_CAPTURE_RESERVED_00004000,
  PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
  PSS_CREATE_BREAKAWAY = 0x08000000,
  PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
  PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
  PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
  PSS_CREATE_RELEASE_SECTION = 0x80000000
} PSS_CAPTURE_FLAGS;

typedef enum  {
  PSS_QUERY_PROCESS_INFORMATION = 0,
  PSS_QUERY_VA_CLONE_INFORMATION = 1,
  PSS_QUERY_AUXILIARY_PAGES_INFORMATION = 2,
  PSS_QUERY_VA_SPACE_INFORMATION = 3,
  PSS_QUERY_HANDLE_INFORMATION = 4,
  PSS_QUERY_THREAD_INFORMATION = 5,
  PSS_QUERY_HANDLE_TRACE_INFORMATION = 6,
  PSS_QUERY_PERFORMANCE_COUNTERS = 7
} PSS_QUERY_INFORMATION_CLASS;

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

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
