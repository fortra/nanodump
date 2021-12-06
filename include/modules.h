#pragma once

#define LSASRV_DLL L"lsasrv.dll"
#ifdef _WIN64
#define LDR_POINTER_OFFSET 0x18
#define MODULE_LIST_POINTER_OFFSET 0x20
#else
#define LDR_POINTER_OFFSET 0xc
#define MODULE_LIST_POINTER_OFFSET 0x14
#endif

Pmodule_info find_modules(HANDLE hProcess, wchar_t* important_modules[], int number_of_important_modules, BOOL is_lsass);
