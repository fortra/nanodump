#pragma once

#if defined(NANO) && !defined(SSP)

#include <windows.h>
#include <winternl.h>

#include "ntdefs.h"
#include "utils.h"
#include "dinvoke.h"

#define NtOpenProcess_SW2_HASH 0xcd9b2a0f

#if defined(__clang__)
 #define SET_SYNTAX ".intel_syntax noprefix \n"
#else
 #define SET_SYNTAX
#endif

#ifdef _WIN64

typedef struct _SYSCALL_DATA
{
    PVOID full_stack_base;        // 0x00
    ULONG_PTR full_stack_size;    // 0x08
    PVOID full_stack_backup_addr; // 0x10
    PVOID fake_stack_heap_addr;   // 0x18
    ULONG_PTR fake_stack_size;    // 0x20
    PVOID fake_stack_target_addr; // 0x28
    PVOID fake_stack_rsp;         // 0x30
    PVOID fake_stack_rbp;         // 0x38
    PVOID canary_addr;            // 0x40
    union {
        PVOID syscall_addr;       // 0x48
        PVOID api_addr;           // 0x48
    };
    ULONG32 syscall_number;       // 0x50
    BOOL is_api_call;             // 0x54
    BOOL is_wow64;                // 0x58
    ULONG32 num_params;           // 0x5c
    ULONG_PTR params[10];         // 0x60+0x8*i
} SYSCALL_DATA, *PSYSCALL_DATA;

#else

typedef struct _SYSCALL_DATA
{
    PVOID full_stack_base;        // 0x00
    ULONG_PTR full_stack_size;    // 0x04
    PVOID full_stack_backup_addr; // 0x08
    PVOID fake_stack_heap_addr;   // 0x0c
    ULONG_PTR fake_stack_size;    // 0x10
    PVOID fake_stack_target_addr; // 0x14
    PVOID fake_stack_rsp;         // 0x18
    PVOID fake_stack_rbp;         // 0x1c
    PVOID canary_addr;            // 0x20
    union {
        PVOID syscall_addr;       // 0x24
        PVOID api_addr;           // 0x24
    };
    ULONG32 syscall_number;       // 0x28
    BOOL is_api_call;             // 0x2c
    BOOL is_wow64;                // 0x30
    ULONG32 num_params;           // 0x34
    ULONG_PTR params[10];         // 0x38+0x4*i
} SYSCALL_DATA, *PSYSCALL_DATA;

#endif

#ifndef UNWIND_HISTORY_TABLE_SIZE

  #define UNWIND_HISTORY_TABLE_SIZE 12

  typedef struct _FRAME_POINTERS {
    ULONGLONG MemoryStackFp;
    ULONGLONG BackingStoreFp;
  } FRAME_POINTERS,*PFRAME_POINTERS;

  typedef struct _RUNTIME_FUNCTION {
      ULONG BeginAddress;
      ULONG EndAddress;
      ULONG UnwindData;
  } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

  typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    ULONG64 ImageBase;
    ULONG64 Gp;
    PRUNTIME_FUNCTION FunctionEntry;
  } UNWIND_HISTORY_TABLE_ENTRY,*PUNWIND_HISTORY_TABLE_ENTRY;

  typedef struct _UNWIND_HISTORY_TABLE {
    ULONG Count;
    UCHAR Search;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
  } UNWIND_HISTORY_TABLE,*PUNWIND_HISTORY_TABLE;

#endif

#ifndef UNW_FLAG_CHAININFO
  #define UNW_FLAG_CHAININFO  0x4
#endif

#define UNUSED(x) (void)(x)

#define MAX_FRAME_NUM 30
#define RBP_OP_INFO 0x5

//
// Used to store information for individual stack frames for call stack to spoof.
//
typedef struct _STACK_FRAME {
    WCHAR targetDll[MAX_PATH];
    WCHAR target_dll_name[MAX_PATH];
    DWORD functionHash;
    CHAR function_name[MAX_PATH];
    ULONG offset;
    ULONG totalStackSize;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
    ULONG32 pattern_size;
    CHAR pattern[256];
    BYTE byte_match[256];
    BOOL is_valid;
    PVOID function_addr;
    ULONG32 final_offset;
    BOOL push_frame;
    BOOL is_exception;
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
    UWOP_EPILOG,
    UWOP_SPARE_CODE,
    UWOP_SAVE_XMM128, /* info == XMM reg number, offset in next slot */
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

typedef struct _STACK_INFO {
    PVOID full_stack_base;
    ULONG64 full_stack_size;
    PVOID full_stack_backup_addr;
    PVOID fake_stack_heap_addr;
    ULONG64 fake_stack_size;
    PVOID fake_stack_target_addr;
    PVOID fake_stack_rsp;
    PVOID fake_stack_rbp;
    PVOID canary_addr;
    PVOID first_ret_addr;
    PVOID storing_area;
} STACK_INFO, *PSTACK_INFO;

BOOL lookup_function_entry(
    IN ULONG_PTR ControlPc,
    PRUNTIME_FUNCTION* pFunctionEntry,
    PVOID* pImageBase);

DWORD64 get_module_base(VOID);

BOOL create_fake_callstack(
    PSTACK_INFO stack_info,
    ULONG32 function_hash);

HANDLE open_handle_with_spoofed_callstack(
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes);

PNT_TIB get_tib();

#endif
