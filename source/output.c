#include "output.h"

#if defined(DDL) && defined(PPL_DUMP)

#ifndef intAlloc
#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#endif
#ifndef intFree
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#endif
#ifndef DATA_FREE
#define DATA_FREE(d, l) \
    if (d) { \
        memset(d, 0, l); \
        intFree(d); \
        d = NULL; \
    }
#endif

VOID LogToConsole(
    IN LPCSTR pwszFormat,
    ...)
{
    //
    // The process in which we load this DLL does not have a console so we need to attach to the 
    // parent process' console. To do so, we can call AttachConsole with the special value 
    // ATTACH_PARENT_PROCESS. Then, we can get the STDOUT handle. This handle is stored will be 
    // stored as a global variable so we need to initialize it only once.
    //
    AttachConsole(ATTACH_PARENT_PROCESS);

    //
    // Prepare otuput string and use WriteConsole instead of wprintf. This way, we can directly use
    // the STDOUT handle we got previously.
    //
    DWORD dwOutputStringSize = 0;
    LPSTR pwszOutputString = NULL;
    va_list va;

    va_start(va, pwszFormat);

    dwOutputStringSize = _vscprintf(pwszFormat, va) + 2; // \0
    pwszOutputString = intAlloc(dwOutputStringSize);

    if (pwszOutputString)
    {
        vsprintf_s(pwszOutputString, dwOutputStringSize, pwszFormat, va);

        WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), pwszOutputString, (DWORD)strlen(pwszOutputString), NULL, NULL);

        DATA_FREE(pwszOutputString, dwOutputStringSize);
    }

    va_end(va);
}
#endif
