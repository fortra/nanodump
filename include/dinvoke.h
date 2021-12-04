#pragma once

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);

PVOID GetFunctionAddress(HMODULE hLibrary, LPCSTR ProcName);
HANDLE GetLibraryAddress(LPCSTR LibName);
