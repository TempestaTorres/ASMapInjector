IMAGE_ORDIANAL_FLAG32       = 80000000h

isvalidpe32                 proto :DWORD
isdll32                     proto :DWORD
get_sectionHDR              proto :DWORD
get_sizeOfImage32           proto :DWORD
get_sizeOfHeaders32         proto :DWORD
get_numberOfSections32      proto :DWORD
get_import_directory32      proto :DWORD
get_import_table_rva32      proto :DWORD
get_reloc_table_rva32       proto :DWORD
rva_to_fileoffset32         proto :DWORD,:DWORD
get_dll_name32              proto :DWORD,:DWORD

.code
;======================================================
;Checks if pe file is valid PE
;returns pointer to pe header
;======================================================
isvalidpe32 proc uses ebx esi edi lpdoshdr:DWORD

    push lpdoshdr
    pop edi
    ;------------
    movzx eax,word ptr[edi]    ;Magic Number MZ (5A4Dh)
    cmp ax,5A4Dh
    jne @@Err
    ;------------
    mov eax,dword ptr[edi+3Ch] ;File address of new exe header
    add edi,eax
    ;------------
    mov eax,dword ptr[edi]     ;Signature (00004550h)
    cmp eax,4550h
    jne @@Err
    ;------------
    push edi
    pop eax
@@Ret:
	ret
@@Err:
    xor eax,eax
    jmp @@Ret
isvalidpe32 endp
;======================================================
isdll32 proc uses ebx esi edi pehdr:DWORD

    mov eax,pehdr
    movzx eax, word ptr[eax+16h]
    test eax,2000h
    setne al
    movzx eax,al
	ret
isdll32 endp
;======================================================
get_sectionHDR proc uses ebx esi edi phdr:DWORD

    mov eax,phdr
    add eax,0F8h
	ret
get_sectionHDR endp
;======================================================
get_sizeOfImage32 proc uses ebx esi edi phdr:DWORD

    mov eax,phdr
    mov eax,dword ptr[eax+50h]
	ret
get_sizeOfImage32 endp
;======================================================
get_sizeOfHeaders32 proc uses ebx esi edi phdr:DWORD

    mov eax,phdr
    mov eax,dword ptr[eax+54h]
	ret
get_sizeOfHeaders32 endp
;======================================================
get_numberOfSections32 proc uses ebx esi edi phdr:DWORD

    mov eax,phdr
    movzx eax,word ptr[eax+6]
	ret
get_numberOfSections32 endp
;======================================================
;returns Import Table Virtual Address 
;======================================================
get_import_table_rva32 proc uses ebx esi edi pehdr:DWORD

    push pehdr
    pop eax
    add eax,80h
    mov eax,dword ptr[eax]
    ;---------------------
	ret
get_import_table_rva32 endp
;======================================================
get_reloc_table_rva32 proc uses ebx esi edi pehdr:DWORD

    push pehdr
    pop eax
    add eax,0A0h
    mov eax,dword ptr[eax]
    ;---------------------
	ret
get_reloc_table_rva32 endp
;======================================================
;returns pointer to ImortDirectory
;======================================================
get_import_directory32 proc uses ebx esi edi pehdr:DWORD

    push pehdr
    pop eax
    add eax,80h

	ret
get_import_directory32 endp
;======================================================
;returns pointer to the string with name of dll 
;from IMAGE_DESCRIPTOR
;======================================================
get_dll_name32 proc uses ebx esi edi base:DWORD,descriptor:DWORD

    push descriptor
    pop eax
    ;--------------
    invoke rva_to_fileoffset32,base,dword ptr[eax+0Ch]
    ;--------------
    add eax,base

	ret
get_dll_name32 endp
;======================================================
;======================================================
;gets file offset by given rva
;======================================================
rva_to_fileoffset32 proc uses ebx esi edi base:DWORD,rva:DWORD

    push rva
    push base
    pop esi
    pop edi
    ;--------------
    add esi,dword ptr[esi+3Ch]    ;PE HDR
    ;--------------
    lea edx,dword ptr[esi+0F8h]   ;section hdr
    movzx ecx,word ptr[esi+6]     ;numberOfsections
    ;---------------
@@For:
    or ecx,ecx
    je @@Done
    ;------------------------------------------
    ;check if rva in range of section addresses
    ;------------------------------------------
    
    cmp edi,dword ptr[edx+0Ch]    ;Begin Section VirtualAddress
    jl @@Next
    ;---------------
    mov eax,dword ptr[edx+0Ch]
    add eax,dword ptr[edx+10h]    ;SizeOfRawData + Virtual Address = EndOfSection
    cmp edi,eax
    jge @@Next
    
    ;------------------------------
    ;The address is in this section
    ;Get file offset rva - virtual address + raw address
    ;------------------------------
    
    mov eax,dword ptr[edx+0Ch]
    sub edi,eax
    mov eax,dword ptr[edx+14h]     ;PointerToRawData
    add eax,edi                    ; eax == file offset
    jmp @@Ret
    ;---------------
@@Next:
    lea edx,dword ptr[edx+40]     ;next section
    dec ecx
    jmp @@For
@@Done:
    
    push edi
    pop eax

@@Ret:
	ret
rva_to_fileoffset32 endp
;======================================================