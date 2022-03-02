#include "output.h"

VOID LogToConsole(LPCSTR pwszFormat, ...)
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
    size_t offset = 0;

    va_start(va, pwszFormat);

    dwOutputStringSize = _vscprintf(pwszFormat, va) + 2; // \0
    pwszOutputString = (LPSTR)LocalAlloc(LPTR, dwOutputStringSize);

    if (pwszOutputString)
    {
        if (SUCCEEDED(StringCbLength(pwszOutputString, dwOutputStringSize, &offset)))
        {
            StringCbVPrintf(&pwszOutputString[offset / sizeof(WCHAR)], dwOutputStringSize - offset, pwszFormat, va);

            WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), pwszOutputString, (DWORD)strlen(pwszOutputString), NULL, NULL);
        }

        LocalFree(pwszOutputString);
    }

    va_end(va);
}
