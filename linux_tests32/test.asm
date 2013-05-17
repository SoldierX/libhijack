BITS 32

;Copyright (c) 2011-2013, Shawn Webb
; All rights reserved.
; 
; Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

;    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
; 
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
