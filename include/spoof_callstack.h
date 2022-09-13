#pragma once

#if defined(NANO) && !defined(SSP)

#include <windows.h>
#include <winternl.h>

#include "ntdefs.h"
#include "utils.h"
#include "dinvoke.h"

#define UNUSED(x) (void)(x)

#define SVC_STACK 1
#define WMI_STACK 2
#define RPC_STACK 3

#define MAX_FRAME_NUM 30
#define MAX_STACK_SIZE 50000
#define RBP_OP_INFO 0x5

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 1

#ifdef _WIN64
typedef PRUNTIME_FUNCTION(NTAPI* RtlLookupFunctionEntry_t)(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);
typedef PVOID(NTAPI* AddVectoredExceptionHandler_t)(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectorHandler);
typedef ULONG(NTAPI* RemoveVectoredExceptionHandler_t)(PVOID Handle);
#endif

#define RtlLookupFunctionEntry_SW2_HASH 0x1B840B1C
#define RtlExitUserThread_SW2_HASH 0x5489B6D7
#define AddVectoredExceptionHandler_SW2_HASH 0x043D5897
#define RemoveVectoredExceptionHandler_SW2_HASH 0x7452A70F

//
// Used to store information for individual stack frames for call stack to spoof.
//
typedef struct _STACK_FRAME {
    WCHAR targetDll[MAX_PATH];
    DWORD functionHash;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} STACK_FRAME, *PSTACK_FRAME;

//
// Unwind op codes: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
//
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
*   union {
*       OPTIONAL ULONG ExceptionHandler;
*       OPTIONAL ULONG FunctionEntry;
*   };
*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

HANDLE open_handle_with_spoofed_callstack(
    IN DWORD stack_type,
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes);

#endif
