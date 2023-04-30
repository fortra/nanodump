
#include "dinvoke.h"

typedef HANDLE(WINAPI* OpenEventW_t)(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);
typedef BOOL(WINAPI* SetEvent_t)(HANDLE hEvent);

#define CreateFileTransactedW_SW2_HASH 0x968D0D41
#define OpenEventW_SW2_HASH            0x9E08A2EF
#define SetEvent_SW2_HASH              0x5A8072DC

BOOL signal_dll_load_event(
    IN LPWSTR event_name);
