OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

.code
PUBLIC WorkCallback

WorkCallback PROC
    sub rsp, 28h            ; Counteract `add rsp, 28h` in the gadget's epilogue; done in this function's "prologue"
    mov rax, [rdx + 8]      ; Put pLoadLibraryAddress into r10; will be called by the gadget
    mov r11, [rdx + 10h]    ; Put pGadgetAddress into r11; will be jumped to
    mov rcx, [rdx]          ; Put LibraryName into rcx, first agument to LoadLibraryA
    xor rdx, rdx            ; Null out rdx (second argument to LoadLibraryExA, already done by LoadLibraryA but to future-proof in case of a switch to LoadLibraryExA)
    xor r8, r8              ; Null out r8 (third argument to LoadLibraryExA, already done by LoadLibraryA but to future-proof in case of a switch to LoadLibraryExA)
    jmp r11                 ; Jmp to the gadget, will not put this function's address in the call stack
WorkCallback ENDP

END
