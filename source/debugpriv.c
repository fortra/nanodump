#include "debugpriv.h"
#if defined(BOF)
#include "dinvoke.c"
#endif

#if defined(NANO) && !defined(SSP)

BOOL enable_debug_priv(void)
{
    // you can remove this function by providing the compiler flag: -DNODPRIV
#ifndef NODPRIV
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tkp;
    LookupPrivilegeValueW_t LookupPrivilegeValueW;
    BOOL ok;

    // find the address of LookupPrivilegeValueW dynamically
    LookupPrivilegeValueW = (LookupPrivilegeValueW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        LookupPrivilegeValueW_SW2_HASH,
        0
    );
    if (!LookupPrivilegeValueW)
    {
        DPRINT_ERR("Address of 'LookupPrivilegeValueW' not found");
        DPRINT_ERR("Could not enable SeDebugPrivilege");
        return FALSE;
    }
    DPRINT(
        "Got address of LookupPrivilegeValueW: 0x%p",
        (PVOID)LookupPrivilegeValueW
    );

    ok = LookupPrivilegeValueW(
        NULL,
        SeDebugPrivilege,
        &tkp.Privileges[0].Luid
    );
    if (!ok)
    {
        function_failed("LookupPrivilegeValueW");
        DPRINT_ERR("Could not enable SeDebugPrivilege");
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
        DPRINT_ERR("Could not enable SeDebugPrivilege");
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
        DPRINT_ERR("Could not enable SeDebugPrivilege");
        return FALSE;
    }
    DPRINT("SeDebugPrivilege enabled");
#endif
    return TRUE;
}

#endif
