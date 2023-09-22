.686P
.model flat,stdcall
option casemap:none
;==========================================
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib

include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib
include iat32.inc

DLL_PROCESS_DETACH    = 0
DLL_PROCESS_ATTACH    = 1
DLL_THREAD_ATTACH     = 2
DLL_THREAD_DETACH     = 3

hMessageBox  proto :DWORD,:DWORD,:DWORD,:DWORD
 
Hook   proto :DWORD
.data 
oldMessageBox    dd 0
user32           db "user32.dll",0
szMessageBox     db "MessageBoxA",0
szText           db "I am the almighty evil punishing sinful programmers",13,10
                 db "with my divine assembler hand!",13,10
                 db "I am the alpha and omega of machine language.",13,10
                 db "And my name is Tempesta!",0
szCaption        db "MASM32 KillBros",0

.code
dll_main proc hInstDll:DWORD,reason:DWORD,unused:DWORD
   
    cmp reason,1
    jne @@Ret
    ;------------
    invoke DisableThreadLibraryCalls,hInstDll
    ;-------------
    ;push 0
    ;push 0
    ;push 0
    ;push offset Hook
    ;push 1000h
    ;push 0
    ;-------------
	;call CreateThread
	push 0
	call Hook

@@Ret:
    xor eax,eax
    inc eax

	ret
dll_main endp
;===================================================================
Hook proc uses ebx esi edi lParam:DWORD
    LOCAL oldprotect:DWORD
    
    push offset user32
    ;-----------------
    call LoadLibrary
    ;-----------------
    or eax,eax
    je @@Ret
    ;-----------------
    push offset szMessageBox
    push eax
    ;-----------------
    call GetProcAddress
    ;-----------------
    or eax,eax
    je @@Ret
    ;-----------------
    mov ebx,eax
    ;-----------------
    invoke GetModuleHandle,0
    ;-----------------
    invoke iat32_get_begin_end,eax
    ;-----------------
    invoke iat32_find,eax,edx,ebx
    ;-----------------
    or eax,eax
    je @@Ret
    ;-----------------
    mov esi,eax
    ;-----------------
    mov eax,dword ptr[esi]
    mov oldMessageBox,eax
    ;------------------
    invoke VirtualProtect,esi, 4, PAGE_EXECUTE_READWRITE, addr oldprotect
    ;------------------
    mov dword ptr[esi],offset hMessageBox
    ;------------------
	invoke VirtualProtect,esi, 4, oldprotect, addr oldprotect
	;------------------
	xor eax,eax
@@Ret:
	ret
Hook endp
;===================================================================
hMessageBox proc hWin:DWORD,lpText:DWORD,lpCaption:DWORD,bType:DWORD

    push bType
    push offset szCaption
    push offset szText
    push hWin
    mov eax,oldMessageBox
    call eax

	ret
hMessageBox endp
;===================================================================
end dll_main