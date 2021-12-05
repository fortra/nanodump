#pragma once

#define MAX_PROCESSES 5000

typedef struct _PROCESS_LIST
{
    ULONG Count;
    ULONG ProcessId[MAX_PROCESSES];
} PROCESS_LIST, *PPROCESS_LIST;

typedef struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

HANDLE duplicate_lsass_handle(DWORD lsass_pid);
HANDLE get_process_handle(DWORD dwPid, DWORD dwFlags, BOOL quiet);
HANDLE fork_lsass_process(DWORD dwPid);
HANDLE find_lsass(void);
