BITS 32

push eax
mov eax, 0x2
push eax
mov eax, 0x22222222
push eax

mov eax, 0x33333333
call eax
pop eax
pop eax
pop eax

ret
