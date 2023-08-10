.code

get_rip PROC
    mov rax, [rsp]
    ret
get_rip ENDP

get_rsp PROC
    lea rax, [rsp+08h]
    ret
get_rsp ENDP

get_tib PROC
	mov rax, gs:[30h]
	ret
get_tib ENDP

jumper PROC
	pop r11
	xor rax, rax
	mov rdx, [rcx+008h]
	mov r8, [rcx+010h]
	mov r9, [rcx]
	bkp_stack_loop1:
	mov r10b, [r9+rax]
	mov [r8+rax], r10b
	inc rax
	cmp rax, rdx
	jne bkp_stack_loop1
	xor rax, rax
	mov r8, [rcx+018h]
	mov r9, [rcx+028h]
	mov rdx, [rcx+020h] 
	cpy_fake_stack_loop1:
	mov r10b, [r8+rax]
	mov [r9+rax], r10b
	inc rax
	cmp rax, rdx
	jne cpy_fake_stack_loop1
	mov rax, [rcx+040h]
	mov rax, [rax+008h]
	mov rdx, [rcx+008h]
	mov [rax+000h], rdx
	mov rdx, [rcx+010h]
	mov [rax+008h], rdx
	mov rdx, [rcx]
	mov [rax+010h], rdx
	mov [rax+018h], rbx
	mov [rax+020h], rbp
	mov [rax+028h], rsp
	mov [rax+030h], r11
	xor rax, rax
	mov eax, [rcx+05ch]
	mov r10, rcx
	cmp eax, 01h
	jl params_ready1
	mov rcx, [r10+060h]
	cmp eax, 02h
	jl params_ready1
	mov rdx, [r10+068h]
	cmp eax, 03h
	jl params_ready1
	mov r8, [r10+070h]
	cmp eax, 04h
	jl params_ready1
	mov r9, [r10+078h]
	sub eax, 04h
	mov rbp, [r10+030h]
	stack_params_loop1:
	cmp eax, 01h
	jl params_ready1
	mov rbx, [r10+078h+rax*08h]
	mov [rbp+020h+rax*08h], rbx
	dec rax
	jmp stack_params_loop1
	params_ready1:
	mov rsp, [r10+030h]
	mov rbp, [r10+038h]
	mov eax, [r10+050h]
	mov r11, [r10+048h]
	mov r10, rcx
	jmp r11
jumper ENDP

end
