.code

hwbp_handler PROC
	mov rax, [rcx]
	mov eax, [rax]
	cmp eax, 080000004h
	jnz leave1
	mov rax, rcx
	mov rcx, [rax+008h]
	mov rax, [rcx+078h]
	mov r11, [rcx+098h]
	mov r9, 0DEADBEEFCAFEBABEh
	search_loop:
	add r11, 08h
	cmp [r11], r9
	jne search_loop
	mov r11, [r11+008h]
	mov rcx, [r11+000h]
	mov rdx, [r11+008h]
	mov r9, [r11+010h]
	mov rbx, [r11+018h]
	mov rbp, [r11+020h]
	mov rsp, [r11+028h]
	mov r8, [r11+030h]
	xor r11, r11
	restore_stack_loop:
	mov r10b, [rdx+r11]
	mov [r9+r11], r10b
	inc r11
	cmp r11, rcx
	jne restore_stack_loop
	jmp r8
	leave1:
	mov eax, 0ffffffffh
	ret
hwbp_handler ENDP

end
