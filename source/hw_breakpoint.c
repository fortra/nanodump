
#include "hw_breakpoint.h"

ULONG_PTR set_bits(
    ULONG_PTR dw,
    int lowBit,
    int bits,
    ULONG_PTR newValue)
{
    ULONG_PTR mask = (1UL << bits) - 1UL;
    dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
    return dw;
}

VOID clear_breakpoint(
    CONTEXT* ctx,
    int index)
{
    //Clear the releveant hardware breakpoint
    switch (index)
    {
        case 0:
            ctx->Dr0 = 0;
            break;
        case 1:
            ctx->Dr1 = 0;
            break;
        case 2:
            ctx->Dr2 = 0;
            break;
        case 3:
            ctx->Dr3 = 0;
            break;
    }
     //Clear DRx HBP to disable for local mode
    ctx->Dr7 = set_bits(ctx->Dr7, (index * 2), 1, 0);
    ctx->Dr6 = 0;
    ctx->EFlags = 0;
}

VOID enable_breakpoint(
    CONTEXT* ctx,
    PVOID address,
    int index)
{
    switch (index)
    {
        case 0:
            ctx->Dr0 = (ULONG_PTR)address;
            break;
        case 1:
            ctx->Dr1 = (ULONG_PTR)address;
            break;
        case 2:
            ctx->Dr2 = (ULONG_PTR)address;
            break;
        case 3:
            ctx->Dr3 = (ULONG_PTR)address;
            break;
    }

    //Set bits 16-31 as 0, which sets
    //DR0-DR3 HBP's for execute HBP
    ctx->Dr7 = set_bits(ctx->Dr7, 16, 16, 0);

    //Set DRx HBP as enabled for local mode
    ctx->Dr7 = set_bits(ctx->Dr7, (index * 2), 1, 1);
    ctx->Dr6 = 0;
}

/*
 * This function is responsible for:
 * 1) find the relevant information after the canary
 * 2) restore the registers
 * 3) restore the original stack
 * 4) return to trigger_syscall/trigger_api
 */

#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) __attribute__((stdcall)) LONG hwbp_handler(
    PEXCEPTION_POINTERS exceptions)
{
    __asm {
        // check that the ExceptionCode is EXCEPTION_SINGLE_STEP
        mov ecx, [esp+0x04]
        mov eax, [ecx]
        mov eax, [eax]
        cmp eax, 0x80000004
        jnz leave
        // ecx: ContextRecord
        mov ecx, [ecx+0x04]
        // get the status
        mov eax, [ecx+0xb0]
        // search for the canary
        // edi: exceptions->ContextRecord->Rsp
        mov edi, [ecx+0xc4]
        mov esi, 0xDEADBEEF
        search_loop:
        add edi, 0x04
        cmp dword ptr [edi], esi
        jne search_loop
        // edi: storing_area
        mov edi, [edi+0x04]
        // restore the original stack
        // full_stack_size
        mov ecx, [edi+0x00]
        // full_stack_backup_addr
        mov esi, [edi+0x04]
        // full_stack_base
        mov edx, [edi+0x08]
        restore_stack_loop:
        mov bl, [esi+ecx-0x1]
        mov [edx+ecx-0x1], bl
        dec ecx
        cmp ecx, 0x0
        jne restore_stack_loop
        // restore registers
        mov ebx, [edi+0x0c]
        mov ebp, [edi+0x10]
        mov esp, [edi+0x14]
        mov edi, [edi+0x18]
        // jump back to the Nt* function
        jmp edi
        leave:
        mov eax, 0xffffffff
        ret
    }
}

#elif defined(__GNUC__)

__declspec(naked) LONG hwbp_handler(
    PEXCEPTION_POINTERS exceptions)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        // check that the ExceptionCode is EXCEPTION_SINGLE_STEP
        "mov rax, [rcx] \n"
        "mov eax, [rax] \n"
        "cmp eax, 0x80000004 \n"
        "jnz leave \n"
        // get the status code
        "mov rax, rcx \n"
        "mov rcx, [rax+0x08] \n"
        "mov rax, [rcx+0x78] \n"
        // search for the canary
        // r11: exceptions->ContextRecord->Rsp
        "mov r11, [rcx+0x98] \n"
        "mov r9, 0xDEADBEEFCAFEBABE \n"
        "search_loop: \n"
        "add r11, 0x8 \n"
        "cmp [r11], r9 \n"
        "jne search_loop \n"
        // r11: storing_area
        "mov r11, [r11+0x08] \n"
        // full_stack_size
        "mov rcx, [r11+0x00] \n"
        // full_stack_backup_addr
        "mov rdx, [r11+0x08] \n"
        // full_stack_base
        "mov r9, [r11+0x10] \n"
        // restore RBX
        "mov rbx, [r11+0x18] \n"
        // restore RBP
        "mov rbp, [r11+0x20] \n"
        // restore RSP
        "mov rsp, [r11+0x28] \n"
        // restore RIP
        "mov r8, [r11+0x30] \n"
        // restore the original stack
        "xor r11, r11 \n"
        "restore_stack_loop: \n"
        "mov r10b, [rdx+r11] \n"
        "mov [r9+r11], r10b \n"
        "inc r11 \n"
        "cmp r11, rcx \n"
        "jne restore_stack_loop \n"
        // jump back to the Nt* function
        "jmp r8 \n"
        "leave: \n"
        "mov eax, 0xffffffff \n"
        "ret \n"
    );
#else
    asm(
        SET_SYNTAX
        // check that the ExceptionCode is EXCEPTION_SINGLE_STEP
        "mov ecx, [esp+0x04] \n"
        "mov eax, [ecx] \n"
        "mov eax, [eax] \n"
        "cmp eax, 0x80000004 \n"
        "jnz leave \n"
        // ecx: ContextRecord
        "mov ecx, [ecx+0x04] \n"
        // get the status
        "mov eax, [ecx+0xb0] \n"
        // search for the canary
        // edi: exceptions->ContextRecord->Rsp
        "mov edi, [ecx+0xc4] \n"
        "mov esi, 0xDEADBEEF \n"
        "search_loop: \n"
        "add edi, 0x04 \n"
        "cmp dword ptr [edi], esi \n"
        "jne search_loop \n"
        // edi: storing_area
        "mov edi, [edi+0x04] \n"
        // restore the original stack
        // full_stack_size
        "mov ecx, [edi+0x00] \n"
        // full_stack_backup_addr
        "mov esi, [edi+0x04] \n"
        // full_stack_base
        "mov edx, [edi+0x08] \n"
        "restore_stack_loop: \n"
        "mov bl, [esi+ecx-0x1] \n"
        "mov [edx+ecx-0x1], bl \n"
        "dec ecx \n"
        "cmp ecx, 0x0 \n"
        "jne restore_stack_loop \n"
        // restore registers
        "mov ebx, [edi+0x0c] \n"
        "mov ebp, [edi+0x10] \n"
        "mov esp, [edi+0x14] \n"
        "mov edi, [edi+0x18] \n"
        // jump back to the Nt* function
        "jmp edi \n"
        "leave: \n"
        "mov eax, 0xffffffff \n"
        "ret \n"
    );
#endif
}

#endif

BOOL set_hwbp(
    PVOID address,
    PHANDLE phHwBpHandler)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hHwBpHandler = NULL;
    CONTEXT threadCtx = { 0 };
    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_ALL;
    RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler = NULL;

    // find the address of RtlAddVectoredExceptionHandler_t dynamically
    RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlAddVectoredExceptionHandler_SW2_HASH,
        0);
    if (!RtlAddVectoredExceptionHandler)
    {
        api_not_found("RtlAddVectoredExceptionHandler");
        goto cleanup;
    }

    hHwBpHandler = RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)hwbp_handler);
    if (!hHwBpHandler)
    {
        function_failed("RtlAddVectoredExceptionHandler");
        goto cleanup;
    }

    status = NtGetContextThread(NtCurrentThread(), &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetContextThread", status);
        goto cleanup;
    }

    enable_breakpoint(&threadCtx, address, DEBUG_REGISTER_INDEX);

    status = NtSetContextThread(NtCurrentThread(), &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetContextThread", status);
        goto cleanup;
    }

    *phHwBpHandler = hHwBpHandler;
    ret_val = TRUE;

cleanup:
    return ret_val;
}

VOID unset_hwbp(
    HANDLE hHwBpHandler)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    CONTEXT threadCtx = { 0 };
    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_ALL;
    ULONG ret_val = 0;
    RtlRemoveVectoredExceptionHandler_t RtlRemoveVectoredExceptionHandler = NULL;

    // find the address of RtlRemoveVectoredExceptionHandler dynamically
    RtlRemoveVectoredExceptionHandler = (RtlRemoveVectoredExceptionHandler_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlRemoveVectoredExceptionHandler_SW2_HASH,
        0);
    if (!RtlRemoveVectoredExceptionHandler)
    {
        api_not_found("RtlRemoveVectoredExceptionHandler");
        goto cleanup;
    }

    status = NtGetContextThread(NtCurrentThread(), &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetContextThread", status);
        goto cleanup;
    }

    clear_breakpoint(&threadCtx, DEBUG_REGISTER_INDEX);

    status = NtSetContextThread(NtCurrentThread(), &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetContextThread", status);
        goto cleanup;
    }

    ret_val = RtlRemoveVectoredExceptionHandler(hHwBpHandler);
    if (!ret_val)
    {
        function_failed("RtlRemoveVectoredExceptionHandler");
        goto cleanup;
    }

cleanup:
    return;
}
