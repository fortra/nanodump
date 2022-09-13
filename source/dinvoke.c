#include "dinvoke.h"

/*
 * Check that hLibrary is indeed a DLL and not something else
 */
BOOL is_dll(
    IN HMODULE hLibrary)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;

    if (!hLibrary)
        return FALSE;

    dos = (PIMAGE_DOS_HEADER)hLibrary;

    // check the MZ magic bytes
    if (dos->e_magic != MZ)
        return FALSE;

    nt = RVA(PIMAGE_NT_HEADERS, hLibrary, dos->e_lfanew);

    // check the NT_HEADER signature
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // check that it is a DLL and not a PE
    USHORT Characteristics = nt->FileHeader.Characteristics;
    if ((Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
        return FALSE;

    return TRUE;
}

/*
 * Look among all loaded DLLs for an export with certain function hash
 */
PVOID find_legacy_export(
    IN HMODULE hOriginalLibrary,
    IN DWORD fhash)
{
    PVOID addr;
    PND_PEB Peb = (PND_PEB)READ_MEMLOC(PEB_OFFSET);
    PND_PEB_LDR_DATA Ldr = Peb->Ldr;
    PVOID FirstEntry = &Ldr->InMemoryOrderModuleList.Flink;
    PND_LDR_DATA_TABLE_ENTRY Entry = (PND_LDR_DATA_TABLE_ENTRY)Ldr->InMemoryOrderModuleList.Flink;

    for (; Entry != FirstEntry; Entry = (PND_LDR_DATA_TABLE_ENTRY)Entry->InMemoryOrderLinks.Flink)
    {
        // avoid looking in the DLL that brought us here
        if (Entry->DllBase == hOriginalLibrary)
            continue;

        // check if this DLL has an export with the function hash we are looking for
        addr = get_function_address(
            Entry->DllBase,
            fhash,
            0);
        if (!addr)
            continue;

        return addr;
    }

    return NULL;
}

/*
 * Follow the reference and return the real address of the function
 */
PVOID resolve_reference(
    IN HMODULE hOriginalLibrary,
    IN PVOID addr)
{
    HANDLE hLibrary;
    PVOID new_addr;
    LPCSTR api;

    // addr points to a string like: NewLibrary.NewFunctionName
    api = &strrchr(addr, '.')[1];
    DWORD dll_length = (DWORD)((ULONG_PTR)api - (ULONG_PTR)addr);
    char dll[MAX_PATH + 1] = {0};
    strncpy(dll, (LPCSTR)addr, dll_length);
    strncat(dll, "dll", MAX_PATH);
    wchar_t wc_dll[MAX_PATH] = {0};
    mbstowcs(wc_dll, dll, MAX_PATH);

    // try to find the library NewLibrary
    hLibrary = get_library_address(wc_dll, FALSE);
    if (!hLibrary)
    {
        // the library is not loaded, meaning it is a legacy DLL
        new_addr = find_legacy_export(
            hOriginalLibrary,
            SW2_HashSyscall(api));

        return new_addr;
    }

    // get the address of NewFunction in NewLibrary
    new_addr = get_function_address(
        hLibrary,
        SW2_HashSyscall(api),
        0);

    return new_addr;
}

/*
 * Find an export in a DLL
 */
PVOID get_function_address(
    IN HMODULE hLibrary,
    IN DWORD fhash,
    IN WORD ordinal)
{
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_DATA_DIRECTORY   data;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   exp_size;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    LPCSTR                  api;
    PVOID                   addr;

    if (!is_dll(hLibrary))
        return NULL;

    dos  = (PIMAGE_DOS_HEADER)hLibrary;
    nt   = RVA(PIMAGE_NT_HEADERS, hLibrary, dos->e_lfanew);
    data = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;

    if (!data->Size || !data->VirtualAddress)
        return NULL;

    exp      = RVA(PIMAGE_EXPORT_DIRECTORY, hLibrary, data->VirtualAddress);
    exp_size = data[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    adr = RVA(PDWORD, hLibrary, exp->AddressOfFunctions);
    sym = RVA(PDWORD, hLibrary, exp->AddressOfNames);
    ord = RVA(PWORD,  hLibrary, exp->AddressOfNameOrdinals);

    addr = NULL;
    if (fhash)
    {
        // iterate over all the exports
        for (DWORD i = 0; i < exp->NumberOfNames; i++)
        {
            api = RVA(LPCSTR, hLibrary, sym[i]);
            //addr = RVA(PVOID, hLibrary, adr[ord[i]]);
            //DPRINT("%lx -> %s -> 0x%llx", fhash, api, (ULONG_PTR)addr-(ULONG_PTR)hLibrary);
            if (fhash == SW2_HashSyscall(api))
            {
                addr = RVA(PVOID, hLibrary, adr[ord[i]]);
                break;
            }
        }
    }
    else
    {
        addr = RVA(PVOID, hLibrary, adr[ordinal - exp->Base]);
    }
    if (!addr)
        return NULL;

    // check if addr is a pointer to another function in another DLL
    if ((ULONG_PTR)addr >= (ULONG_PTR)exp &&
        (ULONG_PTR)addr <  RVA(ULONG_PTR, exp, exp_size))
    {
        // the function seems to be defined somewhere else
        addr = resolve_reference(
            hLibrary,
            addr);
    }
    return addr;
}

/*
 * Get the base address of a DLL
 */
HANDLE get_library_address(
    IN LPWSTR lib_path,
    IN BOOL DoLoad)
{
    PND_PEB Peb = (PND_PEB)READ_MEMLOC(PEB_OFFSET);
    PND_PEB_LDR_DATA Ldr = Peb->Ldr;
    PVOID FirstEntry = &Ldr->InMemoryOrderModuleList.Flink;
    PND_LDR_DATA_TABLE_ENTRY Entry = (PND_LDR_DATA_TABLE_ENTRY)Ldr->InMemoryOrderModuleList.Flink;
    BOOL is_full_path = wcsrchr(lib_path, '\\') ? TRUE : FALSE;

    do
    {
        if (is_full_path)
        {
            // the dll name was provided
            if (!_wcsicmp(lib_path, Entry->FullDllName.Buffer))
                return Entry->DllBase;
        }
        else
        {
            // the full path was provided
            if (!_wcsicmp(lib_path, Entry->BaseDllName.Buffer))
                return Entry->DllBase;
        }

        Entry = (PND_LDR_DATA_TABLE_ENTRY)Entry->InMemoryOrderLinks.Flink;
    } while (Entry != FirstEntry);

    if (!DoLoad)
        return NULL;

    // the library is not currently loaded
    // get the address of LdrLoadDll
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, FALSE),
        LdrLoadDll_SW2_HASH,
        0);
    if (!LdrLoadDll)
    {
        api_not_found("LdrLoadDll");
        return NULL;
    }

    // create a UNICODE_STRING with the library name
    UNICODE_STRING ModuleFileName = { 0 };
    ModuleFileName.Buffer = lib_path;
    ModuleFileName.Length = (USHORT)wcsnlen(ModuleFileName.Buffer, MAX_PATH);
    ModuleFileName.Length *= 2;
    ModuleFileName.MaximumLength = ModuleFileName.Length + 2;

    // load the library
    HANDLE hLibrary = NULL;
    NTSTATUS status = LdrLoadDll(
        NULL,
        0,
        &ModuleFileName,
        &hLibrary);
    if (!NT_SUCCESS(status))
    {
        DPRINT_ERR(
            "Failed to load %ls, status: 0x%lx\n",
            lib_path,
            status);
        return NULL;
    }
    DPRINT("Loaded %ls at 0x%p", lib_path, hLibrary);

    return hLibrary;
}
