#pragma once

#include <windows.h>

#define DLL_NAME_LENGTH 10

BOOL generate_random_dll_path(
    OUT LPSTR* random_path);

BOOL write_ssp_dll(
    IN LPSTR ssp_dll_path,
    IN unsigned char nanodump_ssp_dll[],
    IN unsigned int nanodump_ssp_dll_len);
