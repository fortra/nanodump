#pragma once
#include <windows.h>

#if _WIN64

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0xA02C9FA1 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwGetNextProcess NtGetNextProcess
__asm__("NtGetNextProcess: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x6DB64468 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0xC4572801 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x069597A9 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x012175C4 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__("NtQueryInformationProcess: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x8D2F92AC \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwQueryVirtualMemory NtQueryVirtualMemory
__asm__("NtQueryVirtualMemory: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x03891517 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x2F653BDC \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x3FAF3541 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x4B9E337F \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwCreateFile NtCreateFile
__asm__("NtCreateFile: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x1842C808 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#define ZwWriteFile NtWriteFile
__asm__("NtWriteFile: \n\
	push rcx \n\
	push rdx \n\
	push r8 \n\
	push r9 \n\
	sub rsp, 0x28 \n\
	call GetSyscallAddress \n\
	add rsp, 0x28 \n\
	push rax \n\
	sub rsp, 0x28 \n\
	mov ecx, 0xD057C6EC \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	pop r11 \n\
	pop r9 \n\
	pop r8 \n\
	pop rdx \n\
	pop rcx \n\
	mov r10, rcx \n\
	jmp r11 \n\
");

#else

#define IsWoW64 IsWoW64
__asm__("IsWoW64: \n\
	mov eax, fs:[0xc0] \n\
	test eax, eax \n\
	jne wow64 \n\
	mov eax, 0 \n\
	ret \n\
	wow64: \n\
	mov eax, 1 \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0xA02C9FA1 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwGetNextProcess NtGetNextProcess
__asm__("NtGetNextProcess: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x6DB64468 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0xC4572801 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwClose _NtClose
__asm__("_NtClose: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x069597A9 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x012175C4 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwQueryInformationProcess _NtQueryInformationProcess
__asm__("_NtQueryInformationProcess: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x8D2F92AC \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwQueryVirtualMemory NtQueryVirtualMemory
__asm__("NtQueryVirtualMemory: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x03891517 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x2F653BDC \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x3FAF3541 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x4B9E337F \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwCreateFile _NtCreateFile
__asm__("_NtCreateFile: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0x1842C808 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#define ZwWriteFile NtWriteFile
__asm__("NtWriteFile: \n\
	call GetSyscallAddress \n\
	push eax \n\
	push 0xD057C6EC \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	pop ebx \n\
	mov edx, esp \n\
	sub edx, 4 \n\
	call ebx \n\
	ret \n\
");

#endif
