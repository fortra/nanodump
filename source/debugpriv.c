#include "../include/debugpriv.h"

BOOL strcmp_i(LPCSTR s1, LPCSTR s2)
{
    BOOL matches = TRUE;
    for (int i = 0; s1[i] || s2[i]; i++)
    {
        // make them lower case
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 >= 'A' && c1 <= 'Z')
            c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z')
            c2 += 32;
        if (c1 != c2)
        {
            matches = FALSE;
            break;
        }
    }
    return matches;
}

PVOID GetFunctionAddress(
    HMODULE hLibrary,
    LPCSTR ProcName
)
{
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_EXPORT_DIRECTORY pExpDir;

    if (hLibrary == NULL)
        return NULL;

    pNtHeaders = RVA(
        PIMAGE_NT_HEADERS,
        hLibrary,
        ((PIMAGE_DOS_HEADER)hLibrary)->e_lfanew
    );

    pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (pDataDir->Size)
    {
        pExpDir = RVA(
            PIMAGE_EXPORT_DIRECTORY,
            hLibrary,
            pDataDir->VirtualAddress
        );

        // iterate over all the exports
        for (int i = 0; i < pExpDir->NumberOfNames; i++)
        {
            ULONG32* pRVA = RVA(
                ULONG32*,
                hLibrary,
                pExpDir->AddressOfNames + i * 4
            );
            LPCSTR functionName = RVA(
                LPCSTR,
                hLibrary,
                *pRVA
            );
            if (strcmp_i(functionName, ProcName))
            {
                // found it
                short* pRVA2 = RVA(
                    short*,
                    hLibrary,
                    pExpDir->AddressOfNameOrdinals + i * 2
                );
                ULONG32 FunctionOrdinal = pExpDir->Base + *pRVA2;

                ULONG32* pFunctionRVA = RVA(
                    ULONG32*,
                    hLibrary,
                    pExpDir->AddressOfFunctions + 4 * (FunctionOrdinal - pExpDir->Base)
                );
                PVOID FunctionPtr = RVA(
                    PVOID,
                    hLibrary,
                    *pFunctionRVA
                );
                return FunctionPtr;
            }
        }
    }
    return NULL;
}

HANDLE GetLibraryAddress(
    LPCSTR LibName
)
{
    PSW2_PEB Peb = (PSW2_PEB)READ_MEMLOC(PEB_OFFSET);
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of LibName
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = SW2_RVA2VA(PIMAGE_EXPORT_DIRECTORY, DllBase, VirtualAddress);

        LPCSTR DllName = SW2_RVA2VA(LPCSTR, DllBase, ExportDirectory->Name);
        if (strcmp_i(DllName, LibName))
            return DllBase;
    }
    // avoid an infinite loop
    if (strcmp_i("Kernel32.dll", LibName))
        return NULL;
    // get the address of LoadLibraryA
    LOADLIBRARYA pLoadLibraryA;
    pLoadLibraryA = (LOADLIBRARYA)GetFunctionAddress(
        GetLibraryAddress("Kernel32.dll"),
        "LoadLibraryA"
    );
    // load the library
    return pLoadLibraryA(LibName);
}

BOOL enable_debug_priv(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LOOKUPPRIVILEGEVALUEW pLookupPrivilegeValueW;
    BOOL ok;

    // find the address of LookupPrivilegeValueW dynamically
    pLookupPrivilegeValueW = (LOOKUPPRIVILEGEVALUEW)GetFunctionAddress(
        GetLibraryAddress("Advapi32.dll"),
        "LookupPrivilegeValueW"
    );
    if (!pLookupPrivilegeValueW)
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

    LPCWSTR lpwPriv = L"SeDebugPrivilege";
    ok = pLookupPrivilegeValueW(
        NULL,
        lpwPriv,
        &tkp.Privileges[0].Luid
    );
    if (!ok)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call LookupPrivilegeValueW, error: %ld\n",
            GetLastError()
        );
#endif
        return FALSE;
    }

    NTSTATUS status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &hToken
    );
    if(!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtOpenProcessToken, status: 0x%lx\n",
            status
        );
#endif
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
    NtClose(hToken);
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtAdjustPrivilegesToken, status: 0x%lx\n",
            status
        );
#endif
        return FALSE;
    }

    return TRUE;
}
