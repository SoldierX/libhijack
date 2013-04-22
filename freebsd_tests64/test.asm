BITS 64

;;;;;;;;;;;;;;;
; Call dlopen ;
;;;;;;;;;;;;;;;

push rax
push rbx
mov rax, 0x102
push rax
mov rax, 0x2222222222222222 ; .so filename (string)
push rax
mov rax, 0x3333333333333333 ; addr of dlopen (unsigned long)
call rax

;;;;;;;;;;;;;;
; Call dlsym ;
;;;;;;;;;;;;;;

mov rbx, 0x4444444444444444 ; function name (string)
push rbx
push rax
mov rax, 0x5555555555555555 ; addr of dlsym (unsigned long)
call rax

;;;;;;;;;;;;;;;;;
; Patch PLT/GOT ;
;;;;;;;;;;;;;;;;;

mov rbx, 0x6666666666666666 ; addr of PLT/GOT entry (unsigned long)
mov [rbx], rax

pop rax
pop rax
pop rax
pop rax
pop rbx
pop rax

ret
