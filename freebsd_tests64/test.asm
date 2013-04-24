BITS 64

;;;;;;;;;;;;;;;
; Call dlopen ;
;;;;;;;;;;;;;;;

push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push rsp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
mov rdi, 0x2222222222222222 ; .so filename (string)
mov rsi, 0x102
mov rbx, 0x3333333333333333 ; addr of dlopen (unsigned long)
call rbx

;;;;;;;;;;;;;;
; Call dlsym ;
;;;;;;;;;;;;;;

mov rdi, rax
mov rsi, 0x4444444444444444 ; function name (string)
mov rbx, 0x5555555555555555 ; addr of dlsym (unsigned long)
call rbx

;;;;;;;;;;;;;;;;;
; Patch PLT/GOT ;
;;;;;;;;;;;;;;;;;

mov rbx, 0x6666666666666666 ; addr of PLT/GOT entry (unsigned long)
mov [rbx], rax

pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rsp
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax

ret
