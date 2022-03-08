.code

EXTERN SW3_GetSyscallAddress: PROC
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
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0CD9B2A0Fh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtOpenProcess ENDP

NtGetNextProcess PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0FFBF1A2Fh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtGetNextProcess ENDP

NtReadVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0118B7567h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtReadVirtualMemory ENDP

NtClose PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 02252D33Fh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtClose ENDP

NtOpenProcessToken PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 08FA915A2h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtOpenProcessToken ENDP

NtQueryInformationProcess PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0BDBCBC20h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQueryInformationProcess ENDP

NtQueryVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 00393E980h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQueryVirtualMemory ENDP

NtAdjustPrivilegesToken PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 017AB1B32h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtAdjustPrivilegesToken ENDP

NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 00595031Bh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtAllocateVirtualMemory ENDP

NtFreeVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 001932F05h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtFreeVirtualMemory ENDP

NtCreateFile PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 096018EB6h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtCreateFile ENDP

NtWriteFile PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 024B22A1Ah
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtWriteFile ENDP

NtCreateProcess PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0F538D0A0h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtCreateProcess ENDP

NtQuerySystemInformation PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 04A5B2C8Fh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQuerySystemInformation ENDP

NtDuplicateObject PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 09CBFA413h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtDuplicateObject ENDP

NtQueryObject_ PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 00E23F64Fh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQueryObject_ ENDP

NtWaitForSingleObject PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0426376E3h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtWaitForSingleObject ENDP

NtDeleteFile PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 064B26A1Ah
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtDeleteFile ENDP

NtTerminateProcess PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0652E64A0h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtTerminateProcess ENDP

NtSetInformationProcess_ PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 01D9F320Ch
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtSetInformationProcess_ ENDP

NtQueryInformationToken PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 027917136h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQueryInformationToken ENDP

NtDuplicateToken PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0099C8384h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtDuplicateToken ENDP

NtSetInformationThread PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 01ABE5F87h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtSetInformationThread ENDP

NtCreateDirectoryObjectEx PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0BCBD62EAh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtCreateDirectoryObjectEx ENDP

NtCreateSymbolicLinkObject PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 08AD1BA6Dh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtCreateSymbolicLinkObject ENDP

NtOpenSymbolicLinkObject PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 08C97980Fh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtOpenSymbolicLinkObject ENDP

NtQuerySymbolicLinkObject PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0A63A8CA7h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQuerySymbolicLinkObject ENDP

NtCreateSection PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 0F06912F9h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtCreateSection ENDP

NtOpenThreadToken PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 073A33918h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtOpenThreadToken ENDP

NtCreateTransaction PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 07CAB5EFBh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtCreateTransaction ENDP

NtQueryInformationFile PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 038985C1Eh
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtQueryInformationFile ENDP

NtMakeTemporaryObject PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	mov rcx, 084DF4D82h
	push rcx
	sub rsp, 028h
	call SW3_GetSyscallAddress
	add rsp, 028h
	pop rcx
	push rax
	sub rsp, 028h
	call SW2_GetSyscallNumber
	add rsp, 028h
	pop r11
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11
NtMakeTemporaryObject ENDP

end
