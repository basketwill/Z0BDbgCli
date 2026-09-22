option casemap:none

EXTERN KiUserExceptionDispatcher:PROC
EXTERN m_KiUserExceptionDispatcher:QWORD

PUBLIC FakeKiUserExceptionDispatcher

.code

FakeKiUserExceptionDispatcher PROC
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov r10, rsp
    add r10, 80h
    mov r15, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 20h
    lea rcx, [r10 + 4F0h]
    mov rdx, r10
    call KiUserExceptionDispatcher
    mov rsp, r15
    test eax, eax
    jnz handled

pass_original:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq

    jmp qword ptr [m_KiUserExceptionDispatcher]

handled:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
FakeKiUserExceptionDispatcher ENDP

END
