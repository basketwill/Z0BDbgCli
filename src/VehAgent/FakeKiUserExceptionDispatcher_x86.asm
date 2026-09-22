.386
.model flat, stdcall
option casemap:none

EXTERN KiUserExceptionDispatcher@8:PROC
EXTERN m_KiUserExceptionDispatcher:DWORD

PUBLIC _FakeKiUserExceptionDispatcher

.code

_FakeKiUserExceptionDispatcher PROC
    pushfd
    pushad

    mov eax, dword ptr [esp + 36]
    mov edx, dword ptr [esp + 40]
    push edx
    push eax
    call KiUserExceptionDispatcher@8
    test eax, eax
    jnz handled

pass_original:
    popad
    popfd
    jmp dword ptr [m_KiUserExceptionDispatcher]

handled:
    popad
    popfd
    ret 8
_FakeKiUserExceptionDispatcher ENDP

END
