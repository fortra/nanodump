
#include <windows.h>

#include "dinvoke.h"
#include "output.h"
#include "ntdefs.h"

#define DEBUG_REGISTER_INDEX 0
//#define DEBUG_REGISTER_INDEX 1
//#define DEBUG_REGISTER_INDEX 2
//#define DEBUG_REGISTER_INDEX 3

typedef PVOID(WINAPI* RtlAddVectoredExceptionHandler_t) (ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG(WINAPI* RtlRemoveVectoredExceptionHandler_t) (PVOID Handle);

#define RtlAddVectoredExceptionHandler_SW2_HASH 0xA79DB11D
#define RtlRemoveVectoredExceptionHandler_SW2_HASH 0x24380EA3

#if defined(__clang__)
 #define SET_SYNTAX ".intel_syntax noprefix \n"
#else
 #define SET_SYNTAX
#endif

ULONG_PTR set_bits(
    ULONG_PTR dw,
    int lowBit,
    int bits,
    ULONG_PTR newValue);

VOID clear_breakpoint(
    CONTEXT* ctx,
    int index);

VOID enable_breakpoint(
    CONTEXT* ctx,
    PVOID address,
    int index);

LONG hwbp_handler(
    PEXCEPTION_POINTERS exceptions);

BOOL set_hwbp(
    PVOID address,
    PHANDLE phHwBpHandler);

VOID unset_hwbp(
    HANDLE hHwBpHandler);
