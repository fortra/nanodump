#pragma once
#include <windows.h>

#if _WIN64

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0xA02C9FA1 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwGetNextProcess NtGetNextProcess
__asm__("NtGetNextProcess: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x6DB64468 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0xC4572801 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x069597A9 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x012175C4 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__("NtQueryInformationProcess: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x8D2F92AC \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwQueryVirtualMemory NtQueryVirtualMemory
__asm__("NtQueryVirtualMemory: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x03891517 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x2F653BDC \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x3FAF3541 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x4B9E337F \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateFile NtCreateFile
__asm__("NtCreateFile: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0x1842C808 \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwWriteFile NtWriteFile
__asm__("NtWriteFile: \n\
	mov [rsp +8], rcx \n\
	mov [rsp+16], rdx \n\
	mov [rsp+24], r8 \n\
	mov [rsp+32], r9 \n\
	sub rsp, 0x28 \n\
	mov ecx, 0xD057C6EC \n\
	call SW2_GetSyscallNumber \n\
	add rsp, 0x28 \n\
	mov rcx, [rsp +8] \n\
	mov rdx, [rsp+16] \n\
	mov r8, [rsp+24] \n\
	mov r9, [rsp+32] \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
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

#define DoSysenter
__asm__("DoSysenter: \n\
	mov edx, esp \n\
	sysenter \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	push 0xA02C9FA1 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwGetNextProcess NtGetNextProcess
__asm__("NtGetNextProcess: \n\
	push 0x6DB64468 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	push 0xC4572801 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwClose _NtClose
__asm__("_NtClose: \n\
	push 0x069597A9 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	push 0x012175C4 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwQueryInformationProcess _NtQueryInformationProcess
__asm__("_NtQueryInformationProcess: \n\
	push 0x8D2F92AC \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwQueryVirtualMemory NtQueryVirtualMemory
__asm__("NtQueryVirtualMemory: \n\
	push 0x03891517 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	push 0x2F653BDC \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	push 0x3FAF3541 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
	push 0x4B9E337F \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwCreateFile _NtCreateFile
__asm__("_NtCreateFile: \n\
	push 0x1842C808 \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#define ZwWriteFile NtWriteFile
__asm__("NtWriteFile: \n\
	push 0xD057C6EC \n\
	call SW2_GetSyscallNumber \n\
	add esp, 4 \n\
	call DoSysenter \n\
	ret \n\
");

#endif
