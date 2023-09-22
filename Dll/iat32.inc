
iat32_get_begin_end   proto :DWORD
iat32_find            proto :DWORD,:DWORD,:DWORD

.code 
;================================================================
;returns begin and end addresses of IAT
;eax ==> begin
;edx ==> end
;=================================================================
iat32_get_begin_end proc uses ebx esi edi moduleBaseAddress:DWORD
   
    mov ebx,moduleBaseAddress
    movzx eax,word ptr[ebx]
    cmp eax,5A4Dh
    je @F
    ;---------------
    or eax,eax
    jmp @@Ret
    ;---------------
@@:
    mov eax,dword ptr[ebx+3Ch] ;e_lfanew
    add ebx,eax
    
    ;-------------------
    ;we are at PE HEADER
    ;-------------------
    
    mov edi,dword ptr[ebx+34h]  ;ImageBase
    
    ;-------------------
    ;GET IAT RVA
    ;-------------------
    
    mov eax,dword ptr[ebx+0D8h]
    add eax,edi
    ;-------------------
    mov edx,dword ptr[ebx+0DCh]
    add edx,eax
    ;-------------------
    sub edx,4
@@Ret:
	ret
iat32_get_begin_end endp
;==============================================================
;returns pointer to IAT of the address
;==============================================================
iat32_find  proc uses ebx esi edi iat_begin:DWORD,iat_end:DWORD,search:DWORD

    mov esi,iat_begin
    mov edi,iat_end
    ;-----------------
@@For:
    cmp esi,edi
    je @@End
    ;----------------
    mov eax,dword ptr[esi]
    or eax,eax
    je @@Next
    ;----------------
    mov edx,search
    cmp eax,edx
    jne @@Next
    ;----------------
    mov eax,esi
    jmp @@Ret
@@Next:
    add esi,4
    jmp @@For
@@End:
    xor eax,eax
@@Ret:
	ret
iat32_find endp