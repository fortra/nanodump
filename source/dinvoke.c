#include "dinvoke.h"

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
    DWORD FunctionHash
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
            if (FunctionHash == SW2_HashSyscall(functionName))
            {
                // found it
                PSHORT pRVA2 = RVA(
                    PSHORT,
                    hLibrary,
                    pExpDir->AddressOfNameOrdinals + i * 2
                );
                ULONG32 FunctionOrdinal = pExpDir->Base + *pRVA2;

                PULONG32 pFunctionRVA = RVA(
                    PULONG32,
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
    // the library is not currently loaded
    // avoid an infinite loop
    if (strcmp_i(KERNEL32, LibName))
        return NULL;
    // get the address of LoadLibraryA
    LOADLIBRARYA pLoadLibraryA;
    pLoadLibraryA = (LOADLIBRARYA)GetFunctionAddress(
        GetLibraryAddress(KERNEL32),
        LoadLibraryA_SW2_HASH
    );
    if (!pLoadLibraryA)
        return NULL;
    // load the library
    return pLoadLibraryA(LibName);
}
