#pragma once

#include <windows.h>

#define DLL_NAME_LENGTH 10

typedef PVOID(WINAPI* Sleep_t)(DWORD dwMilliseconds);

#define Sleep_SW2_HASH               0x1AA40C23

BOOL generate_random_dll_path(
    OUT LPSTR* random_path);

BOOL write_ssp_dll(
    IN LPSTR ssp_dll_path,
    IN unsigned char nanodump_ssp_dll[],
    IN unsigned int nanodump_ssp_dll_len);

#if PASS_PARAMS_VIA_NAMED_PIPES == 1
BOOL send_parameters_and_get_result(
    IN LPSTR dump_path,
    IN BOOL use_valid_sig,
    OUT PBOOL dump_worked);
#endif
