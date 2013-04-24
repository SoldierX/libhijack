BITS 64

;;;;;;;;;;;;;;;
; Call dlopen ;
;;;;;;;;;;;;;;;

push rax
push rbx
push rcx
push rsi
push rdi
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

pop rdi
pop rsi
pop rcx
pop rbx
pop rax

ret
