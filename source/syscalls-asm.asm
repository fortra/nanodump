.code

EXTERN GetSyscallAddress: PROC
EXTERN SW2_GetSyscallNumber: PROC

SyscallNotFound PROC
	mov eax, 0C0000225h
	ret
SyscallNotFound ENDP

local_is_wow64 PROC
	mov rax, 0
	ret
local_is_wow64 ENDP

getIP PROC
	mov rax, [rsp]
	ret
getIP ENDP

NtOpenProcess PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0CD9B2A0Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtOpenProcess ENDP

NtGetNextProcess PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0FFBF1A2Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtGetNextProcess ENDP

NtReadVirtualMemory PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0118B7567h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtReadVirtualMemory ENDP

NtClose PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 02252D33Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtClose ENDP

NtOpenProcessToken PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 08FA915A2h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtOpenProcessToken ENDP

NtQueryInformationProcess PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0BDBCBC20h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQueryInformationProcess ENDP

NtQueryVirtualMemory PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 00393E980h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQueryVirtualMemory ENDP

NtAdjustPrivilegesToken PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 017AB1B32h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtAdjustPrivilegesToken ENDP

NtAllocateVirtualMemory PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 00595031Bh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtAllocateVirtualMemory ENDP

NtFreeVirtualMemory PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 001932F05h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtFreeVirtualMemory ENDP

NtCreateFile PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 096018EB6h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtCreateFile ENDP

NtWriteFile PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 024B22A1Ah
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtWriteFile ENDP

NtCreateProcess PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0F538D0A0h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtCreateProcess ENDP

NtQuerySystemInformation PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 04A5B2C8Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQuerySystemInformation ENDP

NtDuplicateObject PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 09CBFA413h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtDuplicateObject ENDP

NtQueryObject_ PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 00E23F64Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQueryObject_ ENDP

NtWaitForSingleObject PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0426376E3h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtWaitForSingleObject ENDP

NtDeleteFile PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 064B26A1Ah
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtDeleteFile ENDP

NtTerminateProcess PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0652E64A0h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtTerminateProcess ENDP

NtSetInformationProcess_ PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 01D9F320Ch
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtSetInformationProcess_ ENDP

NtQueryInformationToken PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 027917136h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQueryInformationToken ENDP

NtDuplicateToken PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0099C8384h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtDuplicateToken ENDP

NtSetInformationThread PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 01ABE5F87h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtSetInformationThread ENDP

NtCreateDirectoryObjectEx PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0BCBD62EAh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtCreateDirectoryObjectEx ENDP

NtCreateSymbolicLinkObject PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 08AD1BA6Dh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtCreateSymbolicLinkObject ENDP

NtOpenSymbolicLinkObject PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 08C97980Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtOpenSymbolicLinkObject ENDP

NtQuerySymbolicLinkObject PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0A63A8CA7h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQuerySymbolicLinkObject ENDP

NtCreateSection PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0F06912F9h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtCreateSection ENDP

NtMapViewOfSection PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 07A2D5C79h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtMapViewOfSection ENDP

NtProtectVirtualMemory PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 03D5335D3h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtProtectVirtualMemory ENDP

NtUnmapViewOfSection PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0CA1ACC8Fh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtUnmapViewOfSection ENDP

NtFlushInstructionCache PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 0B22DB496h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtFlushInstructionCache ENDP

NtOpenThreadToken PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 073A33918h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtOpenThreadToken ENDP

NtCreateTransaction PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 07CAB5EFBh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtCreateTransaction ENDP

NtQueryInformationFile PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 038985C1Eh
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtQueryInformationFile ENDP

NtMakeTemporaryObject PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 028h
	call GetSyscallAddress
	add rsp, 028h
	push rax
	sub rsp, 028h
	mov ecx, 084DF4D82h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	pop r9
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	jmp r11
NtMakeTemporaryObject ENDP

end
