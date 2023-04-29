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
    msg_type_parameters,
    msg_type_result,
} MESSAGE_TYPE;

typedef struct _MSG_PPL_MEDIC_PARAMETERS
{
    LPSTR dump_path[MAX_PATH + 1];
    BOOL  use_valid_sig;
    BOOL  elevate_handle;
} MSG_PPL_MEDIC_PARAMETERS, * PMSG_PPL_MEDIC_PARAMETERS;

typedef struct _MSG_RESULT
{
	BOOL succeded;
} MSG_RESULT, * PMSG_RESULT;

typedef struct _IPC_MSG
{
    MESSAGE_TYPE Type;
    union {
        MSG_RESULT Result;
        MSG_PPL_MEDIC_PARAMETERS Params;
    } p;

} IPC_MSG, * PIPC_MSG;

#if defined(PPL_MEDIC)

#define IPC_PIPE_NAME L"NanoDumpPPLmedicPipe"

#elif defined(SSP)

#define IPC_PIPE_NAME L"NanoDumpSSPPipe"

#endif // #if defined(PPL_MEDIC)

BOOL server_create_named_pipe(
    IN LPCWSTR pipe_name,
    IN BOOL async,
    OUT PHANDLE hPipe);

BOOL client_connect_to_named_pipe(
    IN LPWSTR pipe_name,
    OUT PHANDLE hPipe);

BOOL server_listen_on_named_pipe(
    IN HANDLE hPipe);

BOOL server_recv_arguments_from_pipe(
    IN HANDLE hPipe,
    OUT LPSTR* dump_path,
    OUT PBOOL use_valid_sig,
    OUT PBOOL elevate_handle);

BOOL client_send_arguments_from_pipe(
    IN HANDLE hPipe,
    IN LPSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL elevate_handle);

BOOL server_disconnect_pipe(
    IN HANDLE hPipe);

BOOL write_data_to_pipe(
    IN HANDLE hPipe,
    IN PVOID data_bytes,
    IN DWORD data_size);

BOOL server_send_success(
    IN HANDLE hPipe,
    IN BOOL succeded);

BOOL client_recv_success(
    IN HANDLE hPipe,
    OUT PBOOL succeded);

#endif // #if defined(PPL_MEDIC) || defined(SSP)
