BITS 32

;;;;;;;;;;;;;;;
; Call dlopen ;
;;;;;;;;;;;;;;;

push eax
push ebx
mov eax, 0x2
push eax
mov eax, 0x22222222 ; .so filename (string)
push eax
mov eax, 0x33333333 ; addr of dlopen (unsigned long)
call eax

;;;;;;;;;;;;;;
; Call dlsym ;
;;;;;;;;;;;;;;

mov ebx, 0x44444444 ; function name (string)
push ebx
push eax
mov eax, 0x55555555 ; addr of dlsym (unsigned long)
call eax

;;;;;;;;;;;;;;;;;
; Patch PLT/GOT ;
;;;;;;;;;;;;;;;;;

mov ebx, 0x66666666 ; addr of PLT/GOT entry (unsigned long)
mov [ebx], eax

pop eax
pop eax
pop eax
pop eax
pop ebx
pop eax

ret
