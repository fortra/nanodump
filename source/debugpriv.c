#include "../include/debugpriv.h"
#include "dinvoke.c"

BOOL enable_debug_priv(void)
{
    // you can remove this function by providing the compiler flag: -DNODPRIV
#ifndef NODPRIV
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LOOKUPPRIVILEGEVALUEW LookupPrivilegeValueW;
    BOOL ok;

    // find the address of LookupPrivilegeValueW dynamically
    LookupPrivilegeValueW = (LOOKUPPRIVILEGEVALUEW)GetFunctionAddress(
        GetLibraryAddress(ADVAPI32),
        LookupPrivilegeValueW_SW2_HASH
    );
    if (!LookupPrivilegeValueW)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Address of 'LookupPrivilegeValueW' not found\n"
        );
#endif
        return FALSE;
    }

    ok = LookupPrivilegeValueW(
        NULL,
        SeDebugPrivilege,
        &tkp.Privileges[0].Luid
    );
    if (!ok)
    {
        function_failed("LookupPrivilegeValueW");
        return FALSE;
    }

    NTSTATUS status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &hToken
    );
    if(!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcessToken", status);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    status = NtAdjustPrivilegesToken(
        hToken,
        FALSE,
        &tkp,
        sizeof(TOKEN_PRIVILEGES),
        NULL,
        NULL
    );
    NtClose(hToken); hToken = NULL;
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtAdjustPrivilegesToken", status);
        return FALSE;
    }
#endif
    return TRUE;
}
