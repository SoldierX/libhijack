BITS 32

push long 0x11111111
push eax
push long 0x22222222
push byte 0x2

mov eax, 0x33333333
call eax
pop eax
pop eax
pop eax
ret
