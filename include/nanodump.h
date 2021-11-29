#pragma once

#include <windows.h>

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define MAX_PROCESSES 5000

#define STATUS_PARTIAL_COPY 0x8000000D
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define STATUS_INVALID_CID 0xC000000B
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define SystemHandleInformation 0x10
#define ObjectTypeInformation 2

#define CALLBACK_FILE       0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09

#define MEM_COMMIT 0x1000
//#define MEM_IMAGE 0x1000000
#define MEM_MAPPED 0x40000
#define PAGE_NOACCESS 0x01
#define PAGE_GUARD 0x100

// 70 MiB
#define DUMP_MAX_SIZE 0x4600000
// 900 KiB
#define CHUNK_SIZE 0xe1000

#ifndef _WIN64
// x86 has conflicting types with these functions
#define NtClose _NtClose
#define NtQueryInformationProcess _NtQueryInformationProcess
#define NtCreateFile _NtCreateFile
#define NtQuerySystemInformation _NtQuerySystemInformation
#define NtQueryObject _NtQueryObject
#endif

#ifdef _WIN64
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

#ifdef BOF

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);

WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

WINBASEAPI char *__cdecl MSVCRT$strrchr(const char *_Str,int _Ch);
WINBASEAPI void * __cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI size_t __cdecl MSVCRT$strnlen(const char *s, size_t maxlen);
WINBASEAPI size_t __cdecl MSVCRT$wcsnlen(const wchar_t *_Src,size_t _MaxCount);
WINBASEAPI wchar_t * __cdecl MSVCRT$wcscpy(wchar_t * __restrict__ __dst, const wchar_t * __restrict__ __src);
WINBASEAPI size_t __cdecl MSVCRT$mbstowcs(wchar_t * __restrict__ _Dest,const char * __restrict__ _Source,size_t _MaxCount);
WINBASEAPI wchar_t * __cdecl MSVCRT$wcsncat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source,size_t _Count);
WINBASEAPI int    __cdecl MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1,const wchar_t *_Str2);
WINBASEAPI void WINAPI MSVCRT$srand(int initial);
WINBASEAPI int WINAPI MSVCRT$rand();
WINBASEAPI time_t WINAPI MSVCRT$time(time_t *time);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);

#else

#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$HeapFree HeapFree
#define KERNEL32$GetLastError GetLastError

#define ADVAPI32$LookupPrivilegeValueW LookupPrivilegeValueW

#define MSVCRT$strrchr strrchr
#define MSVCRT$memcpy memcpy
#define MSVCRT$strnlen strnlen
#define MSVCRT$wcsnlen wcsnlen
#define MSVCRT$wcscpy wcscpy
#define MSVCRT$mbstowcs mbstowcs
#define MSVCRT$wcsncat wcsncat
#define MSVCRT$strncmp strncmp
#define MSVCRT$_wcsicmp _wcsicmp
#define MSVCRT$srand srand
#define MSVCRT$rand rand
#define MSVCRT$time time
#define MSVCRT$memset memset

#endif

struct MiniDumpHeader
{
     ULONG32       Signature;
     SHORT         Version;
     SHORT         ImplementationVersion;
     ULONG32       NumberOfStreams;
     ULONG32       StreamDirectoryRva;
     ULONG32       CheckSum;
     ULONG32       Reserved;
     ULONG32       TimeDateStamp;
     ULONG32       Flags;
};

struct MiniDumpDirectory
{
     ULONG32       StreamType;
     ULONG32       DataSize;
     ULONG32       Rva;
};

struct dump_context
{
    HANDLE  hProcess;
    void*   BaseAddress;
    ULONG32 rva;
    char*   signature;
};

struct MiniDumpSystemInfo
{
    SHORT ProcessorArchitecture;
    SHORT ProcessorLevel;
    SHORT ProcessorRevision;
    char    NumberOfProcessors;
    char    ProductType;
    ULONG32 MajorVersion;
    ULONG32 MinorVersion;
    ULONG32 BuildNumber;
    ULONG32 PlatformId;
    ULONG32 CSDVersionRva;
    SHORT SuiteMask;
    SHORT Reserved2;
#if _WIN64
        ULONG64 ProcessorFeatures1;
        ULONG64 ProcessorFeatures2;
#else
        ULONG32 VendorId1;
        ULONG32 VendorId2;
        ULONG32 VendorId3;
        ULONG32 VersionInformation;
        ULONG32 FeatureInformation;
        ULONG32 AMDExtendedCpuFeatures;
#endif
};

struct LDR_DATA_TABLE_ENTRY
{
    //struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    PVOID DllBase;                                                          //0x30
    PVOID EntryPoint;                                                       //0x38
    ULONG32 SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
};

struct module_info
{
    struct module_info* next;
    PVOID dll_base;
    ULONG32 size_of_image;
    char dll_name[256];
    ULONG32 name_rva;
};

struct VsFixedFileInfo
{
    ULONG32 dwSignature;
    ULONG32 dwStrucVersion;
    ULONG32 dwFileVersionMS;
    ULONG32 dwFileVersionLS;
    ULONG32 dwProductVersionMS;
    ULONG32 dwProductVersionLS;
    ULONG32 dwFileFlagsMask;
    ULONG32 dwFileFlags;
    ULONG32 dwFileOS;
    ULONG32 dwFileType;
    ULONG32 dwFileSubtype;
    ULONG32 dwFileDateMS;
    ULONG32 dwFileDateLS;
};

struct MiniDumpLocationDescriptor
{
    ULONG32 DataSize;
    ULONG32 rva;
};

struct MiniDumpModule
{
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    struct VsFixedFileInfo VersionInfo;
    struct MiniDumpLocationDescriptor CvRecord;
    struct MiniDumpLocationDescriptor MiscRecord;
    ULONG64 Reserved0;
    ULONG64 Reserved1;
};

struct MiniDumpMemoryDescriptor64
{
    struct MiniDumpMemoryDescriptor64* next;
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
};

struct linked_list
{
    struct linked_list* next;
};

typedef struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_LIST
{
    ULONG Count;
    ULONG ProcessId[MAX_PROCESSES];
} PROCESS_LIST, *PPROCESS_LIST;
