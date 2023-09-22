;===================================================
MANUAL_INJECT struct

     ImageBase       DWORD ? ;+0
     NtHeaders       DWORD ? ;+4
     BaseRelocation  DWORD ? ;+8	
     ImportDirectory DWORD ? ;+C	
     pLoadLibraryA   DWORD ? ;+10h	
     pGetProcAddress DWORD ? ;+14h

MANUAL_INJECT ends
;======================================================

loader_write    proto :DWORD,:DWORD,:DWORD,:DWORD
;======================================================
;Disassembly:

;0:  60                      pusha
;1:  e8 00 00 00 00          call   0x6
;6:  5b                      pop    ebx
;7:  81 eb 06 00 00 00       sub    ebx,0x6
;d:  b8 cc cc cc cc          mov    eax,0xcccccccc  ;load_dll
;12: ba cc cc cc cc          mov    edx,0xcccccccc  ;pointer to MANUAL_INJECT
;17: 52                      push   edx
;18: ff d0                   call   eax
;1a: 61                      popa
;1b: 68 cc cc cc cc          push   0xcccccccc       ;eip
;20: c3                      ret

.data
shellcode db 60h,0E8h,00h,00h,00h,00h,5Bh,81h,0EBh,06h,00h,00h,00h,0B8h,0CCh,0CCh,0CCh,0CCh,0BAh,0CCh,0CCh,0CCh,0CCh,52h,0FFh,0D0h,61h,68h,0CCh,0CCh,0CCh,0CCh,0C3h
shellsize equ $-shellcode
.code
load_dll proc mi:DWORD
    LOCAL delta:DWORD
    LOCAL countEntrys:DWORD
    LOCAL OrigFirstThunk:DWORD
    LOCAL FirstThunk:DWORD
    LOCAL hModule:DWORD
 
    mov ebx,mi
    
    ;-----------------------------------------------------
    ;delta is offset of allocated memory in target process
    ;-----------------------------------------------------
    
    mov eax,dword ptr[ebx]         ;ImageBase dll
    mov edx,dword ptr[ebx+4]       ;PE HDR
    mov edx,dword ptr[edx+34h]     ;+34 PeHDR->OptionalHDR->ImageBase
    sub eax,edx
    mov delta,eax
    
    ;------------------------------
    ;The process of relocating
    ;------------------------------
    
    mov esi,dword ptr[ebx+8]  ;BaseRelocation
    ;-----------------
@@While:
    mov eax, dword ptr[esi]   ;VirtualAddres
    or eax,eax
    je @@End
    ;-----------------
    mov eax,dword ptr[esi+4]   ;SizeOfBlock
    cmp eax,8
    jle @@Next
    
    ;--------------------------
    ;colculate number of entrys
    ;--------------------------
    
    sub eax,8
    shr eax,1
    mov countEntrys,eax
    ;--------------------------
    lea edi,dword ptr[esi+8]         ; ArrayOfEntrys
    ;--------------------------
    xor ecx,ecx
@@For:
    movzx eax, word ptr[edi+ecx*2]   ;Entry
    and eax,0FFFh                    ;Last 12 bits of RVA
    ;---------------------
    mov edx,dword ptr[esi]           ;VirtualAddress
    add eax,edx                      ;VirtualAddress + Entry RVA
    mov edx,dword ptr[ebx]           ;ImageBase Dll
    add eax,edx           
    ;---------------------
    ;fix reloc
    ;---------------------
    mov edx,dword ptr[eax]
    add edx,delta
    mov dword ptr[eax],edx
    ;---------------------
    ;add edi,2
    inc ecx
    cmp ecx,countEntrys
    jl @@For
    
@@Next:
    mov eax,dword ptr[esi+4]         ;SizeOfBlock
    add esi,eax  
    jmp @@While
     
@@End:   
    ;--------------------
    ;Resolve DLL imports
    ;--------------------
    
    mov esi,dword ptr[ebx+0Ch]         ;ImportDirectory
    
    ;----------------------------------
    ;Loop throug Image Descriptor Array
    ;----------------------------------
@@While2:
    mov eax,dword ptr[esi]             ;OriginalThunk
    or eax,eax
    jne @F
    ;--------------------
    mov eax,dword ptr[esi+10h]         ;FirstThunk
    or eax,eax
    je @@End2
@@:
    mov edx,dword ptr[ebx]             ;Dll ImageBase
    add eax,edx
    mov OrigFirstThunk,eax
    ;--------------------
    mov eax,dword ptr[esi+10h]
    add eax,edx
    mov FirstThunk,eax
    ;--------------------
    mov eax,dword ptr[esi+0Ch]         ;Dll Name
    add eax,edx
    push eax
    ;---------------------
    mov edx,dword ptr[ebx+10h]         ;pLoadLibraryA
    call edx
    ;----------------------
    mov hModule,eax
    ;----------------------
    or eax,eax
    je @@Ret
    ;----------------------
    mov edi,OrigFirstThunk
    
    ;----------------------
    ;FIX FUNCTON ADDRESSES
    ;----------------------
    
@@While3:
    mov eax,dword ptr[edi]
    or eax,eax
    je @@End3
    ;----------------------
    test eax,IMAGE_ORDIANAL_FLAG32
    je @@ByName
    
    ;----------------------
    ;Import by ordinal
    ;----------------------
    
    and eax,0FFFFh
    push eax
    push hModule
    mov edx,dword ptr[ebx+14h]    ;pGetProcAddress
    call edx
    ;----------------------
    or eax,eax
    je @@Ret
    ;----------------------
    mov edx,FirstThunk
    mov dword ptr[edx],eax
    
    jmp @@Next2
@@ByName:
    ;---------------------
    ;Import by name
    ;---------------------
    
    mov edx,dword ptr[ebx]       ;ImageBase
    add eax,edx
    add eax,2                    ;Hint
    ;---------------------
    push eax
    push hModule
    mov edx,dword ptr[ebx+14h]   ;pGetProcAddress
    call edx
    ;----------------------
    or eax,eax
    je @@Ret
    ;----------------------
    mov edx,FirstThunk
    mov dword ptr[edx],eax

@@Next2:
    ;---------------------
    add edi,4
    add FirstThunk,4
    jmp @@While3
@@End3:
    add esi,20                           ;Next Image Descriptor
    jmp @@While2
    
@@End2:
    ;---------------------
    ;LOAD INJECTED DLL
    ;---------------------
    
    mov edx,dword ptr[ebx+4]             ;PE HDR
    mov eax,dword ptr[edx+28h]           ;+28  (40)AddressOfEntryPoint
    or eax,eax
    je @F
    ;---------------------
    mov edx,dword ptr[ebx]               ;IMageBase
    add eax,edx                          ;Dll_Main = EntryPoint + ImageBase
    ;---------------------
    push 0
    push 1
    push edx
    ;---------------------
    call eax
    ;---------------------
    jmp @@Ret
    
@@:
    xor eax,eax
    inc eax
    
@@Ret:
	ret
load_dll endp
;===================================================
;This is used to calculate the size of the shellcode
;===================================================
load_dll_end proc
    
    xor eax,eax
	ret
load_dll_end endp
;===================================================
loader_write proc uses ebx esi edi hProcess:DWORD,mem_loder:DWORD,mem_process_dll:DWORD,dll_base:DWORD
   LOCAL mi:MANUAL_INJECT
   
   mov eax,mem_process_dll
   mov mi.ImageBase,eax
   ;-------------------
   mov esi,dll_base
   mov ebx,dword ptr[esi+3Ch]
   add eax,ebx
   ;-------------------
   mov mi.NtHeaders,eax
   ;-------------------
   add ebx,esi            ;pehdr
   ;-------------------
   mov edx,ebx
   add edx,0A0h
   mov edx,dword ptr[edx] ;reloc rva
   ;-------------------
   mov eax,mem_process_dll
   add eax,edx
   mov mi.BaseRelocation,eax
   ;--------------------
   mov edx,ebx
   add edx,80h
   mov edx,dword ptr[edx] ;it rva
   ;--------------------
   mov eax,mem_process_dll
   add eax,edx
   mov mi.ImportDirectory,eax
   ;--------------------
   fn get_PEBFunction32, offset kernelName, offset szLoadLibrary
   ;--------------------
   mov mi.pLoadLibraryA,eax
   ;--------------------
   fn get_PEBFunction32, offset kernelName, offset szGetProcAddress
   ;--------------------
   mov mi.pGetProcAddress,eax
   
   ;--------------------
   printf("\nWriting loader code to target process.\n")
   ;--------------------
   
   mov edi,mem_loder
   
   ;----------------------------------------------
   ;Write the loader information to target process
   ;----------------------------------------------
   
   fn WriteProcessMemory,hProcess,edi,addr mi,sizeof MANUAL_INJECT,NULL
   
   ;----------------------------------------------
   ;    Write the loader code to target process
   ;----------------------------------------------
   
   add edi,sizeof MANUAL_INJECT
   ;---------------------------
   mov edx,offset load_dll_end
   mov eax,offset load_dll
   sub edx,eax
   ;----------------------------
   fn WriteProcessMemory,hProcess,edi,&load_dll,edx,NULL
   ;-----------------------------
   mov eax,mem_loder
   
   
	ret
loader_write endp
;===================================================
shellcode_setup proc uses ebx esi edi mem_loader:DWORD,rip:DWORD

   ;-----------------------------
   ;Allocate memory for shellcode
   ;-----------------------------
   
   fn VirtualAlloc,NULL,65536,MEM_COMMIT or MEM_RESERVE,PAGE_READWRITE
   ;-----------------
   mov edi,eax
   mov esi,offset shellcode
   
   ;-----------------
   ;   Copy code
   ;-----------------

    xor ebx,ebx
@@:
   mov al,byte ptr[esi+ebx]
   mov byte ptr[edi+ebx],al
   ;-----------------
   inc ebx
   cmp ebx,shellsize
   jl @B
   ;-----------------
   mov eax,mem_loader
   mov dword ptr[edi+13h],eax
   ;-----------------
   add eax,sizeof MANUAL_INJECT
   mov dword ptr[edi+0Eh],eax
   ;-----------------
   mov eax,rip
   mov dword ptr[edi+1Ch],eax
   ;-----------------
   mov eax,edi

	ret
shellcode_setup endp
;===================================================