
MAX_API_STRING_LENGTH     = 150
;NOTE: module hashes are computed using all-caps unicode strings

KERNEL32DLL_HASH				= 6A4ABC5Bh
NTDLLDLL_HASH					= 3CFA685Dh
LOADLIBRARYA_HASH				= 726774ch
GETPROCADDRESS_HASH				= 7802f749h
VIRTUALALLOC_HASH				= 0e553a458h
EXITTHREAD_HASH					= 0a2a1de0h
NTFLUSHINSTRUCTIONCACHE_HASH	= 945cb1afh
RTLEXITUSERTHREAD_HASH			= 0FF7F061Ah 
;Vista+
GETNATIVESYSTEMINFO_HASH	    = 959e0033h
VIRTUALPROTECT_HASH				= 0c38ae110h
MESSAGEBOXA_HASH				= 7568345h
LOCALFREE_HASH					= 0ea61fcb1h			
VIRTUALFREE_HASH				= 300f2f0bh
SLEEP_HASH						= 0e035f044h
RTLADDFUNCTIONTABLE_HASH		= 45b82ebah
LDRLOADDLL_HASH					= 0bdbf9c13h 
LDRGETPROCADDRESS_HASH			= 5ed941b5h 

LOADLYBRARY_OFFSET              = 21270h 
NTGETNEXTTHREAD_OFFSET          = 73A10h

TIB_INFO struct

    seh	         DWORD  ?
    topstack	 DWORD  ?
    bottomstack	 DWORD  ?
    tibOffset	 DWORD  ?
    
TIB_INFO ends

TEB_INFO struct

    ProcessId	                 DWORD ?
    threadId	                 DWORD ?  
    ThreadLocalStoragePointer    DWORD ? 
    Peb	                         DWORD ? 
    LastErrorValue	             DWORD ? 
    ExceptionCode	             DWORD ?
    TlsSlots                     DWORD ?

TEB_INFO ends

ANTIDEBUG_INFO struct

    BeingDebugged     DWORD ?
    NtGlobalFlag      DWORD ?
    WoW64NtGlobalFlag DWORD ?
    HeapFlags         DWORD ?
    ForceFlags        DWORD ?

ANTIDEBUG_INFO ends

get_tibinfo32                            proto :DWORD
get_tebinfo32                            proto :DWORD
get_debuginfo32                          proto :DWORD

get_pebBaseAddress32                     proto
get_pebLdrData32                         proto 
get_ProcessParameters32                  proto :DWORD
get_PEBFunction32                        proto :DWORD,:DWORD
get_ModuleFullPath32                     proto
get_ModuleEntryPoint32                   proto
get_ModuleImageBase32                    proto
get_ProcessCurDir32                      proto
get_ImageBase32                          proto
get_ProcessHeap                          proto
get_ProcessHeapFlags                     proto
get_ProcessHeapForceFlags                proto
get_ProcessId                            proto
get_ProcessThreadId                      proto
get_LastErrorValue                       proto
is_BeingDebugged                         proto
is_NtGlobalFlag                          proto

get_ProcAddr32                           proto :DWORD,:DWORD
get_ProcAddressWithHash32                proto :DWORD

get_InMemoryOrderModuleListFlink         proto :DWORD
get_InInitializationOrderModuleListFlink proto 

get_kernel32base                         proto
get_kernelbase32base                     proto
get_ntdll32base                          proto

.data
ntdllName        dw 'n','t','d','l','l','.','d','l','l',0
kernelbaseName   dw 'K','E','R','N','E','L','B','A','S','E','.','d','l','l',0
kernelName       dw 'K','E','R','N','E','L','3','2','.','D','L','L',0

;--------------------------------------
szLoadLibrary           db "LoadLibraryA",0
szGetProcAddress        db "GetProcAddress",0
szVirtualAlloc          db "VirtualAlloc",0
szVirtualFree           db "VirtualFree",0
szVirtualProtect        db "VirtualProtect",0
szFlushInstructionCache db "FlushInstructionCache",0
szGetNativeSystemInfo   db "GetNativeSystemInfo",0
szSleep                 db "Sleep",0
szRtlAddFunctionTable   db "RtlAddFunctionTable",0

szNtQueueApcThread      db "NtQueueApcThread",0
szNtQueueApcThreadEx    db "NtQueueApcThreadEx",0
szNtAllocateReserveObject db "NtAllocateReserveObject",0

szUser32                db "user32",0
;-------------------------------------
@LoadLibraryA           dd 0
@GetProcAddress         dd 0
.code
get_pebBaseAddress32 proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+30h]
	ret
get_pebBaseAddress32 endp
;=======================================================
get_pebLdrData32 proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+30h]
    ;-------------------------
    mov eax,dword ptr[eax+0Ch]   ;EAX contains the address of the PEB_LDR_DATA structure.
	ret
get_pebLdrData32 endp
;=======================================================
get_ProcessParameters32 proc uses ebx esi edi peb:DWORD

    mov eax,peb
    ;-------------------------
    mov eax,dword ptr[eax+10h]   ;EAX contains the address of the RTL_USER_PROCESS_PARAMETERS structure.
	ret
get_ProcessParameters32 endp
;=======================================================
get_InMemoryOrderModuleListFlink proc uses ebx esi edi ldr:DWORD

    mov eax,ldr
    mov eax,dword ptr[eax+14h] ;EAX is the address of PEB-> Ldr.InMemoryOrderModuleListFlink.Flink
	ret
get_InMemoryOrderModuleListFlink endp
;=======================================================
get_tibinfo32 proc uses ebx esi edi ti:DWORD

    mov esi,ti
    ;----------------
    assume fs:nothing
    mov eax,dword ptr fs:[0]
    mov dword ptr[esi],eax
    ;----------------
    mov eax,dword ptr fs:[4]
    mov edx,dword ptr fs:[8]
    ;----------------
    mov dword ptr[esi+4],eax
    mov dword ptr[esi+8],edx
    ;----------------
    mov eax,dword ptr fs:[18h]
    mov dword ptr[esi+0Ch],eax
    ;----------------
    mov eax,esi

	ret
get_tibinfo32 endp
;==============================================================
get_tebinfo32 proc uses ebx esi edi ti:DWORD

    mov esi,ti
    ;----------------
    assume fs:nothing
    mov eax,dword ptr fs:[20h]
    mov edx,dword ptr fs:[24h]
    mov dword ptr[esi+TEB_INFO.ProcessId],eax
    mov dword ptr[esi+TEB_INFO.threadId],edx
    ;----------------
    mov eax,dword ptr fs:[2Ch]
    mov dword ptr[esi+TEB_INFO.ThreadLocalStoragePointer],eax
    ;----------------
    mov eax,dword ptr fs:[30h]
    mov dword ptr[esi+TEB_INFO.Peb],eax
    ;----------------
    mov eax,dword ptr fs:[34h]
    mov dword ptr[esi+TEB_INFO.LastErrorValue],eax
    ;----------------
    mov eax,dword ptr fs:[5Ch]
    mov dword ptr[esi+TEB_INFO.ExceptionCode],eax
    ;----------------
    mov eax,dword ptr fs:[0C0h]
    mov dword ptr[esi+TEB_INFO.TlsSlots],eax
    ;----------------
    mov eax,esi

	ret
get_tebinfo32 endp
;==============================================================
get_debuginfo32 proc uses ebx esi edi ai:DWORD

    mov esi,ai
    ;----------------
    assume fs:nothing
    ;----------------
    mov ebx,dword ptr fs:[30h]
    movzx eax,byte ptr[ebx+2]
    mov dword ptr[esi],eax
    ;----------------
    mov eax,dword ptr[ebx+68h]
    mov dword ptr[esi+4],eax
    ;----------------
    mov eax,dword ptr fs:[18h]
    sub eax, 2000h
    mov eax,dword ptr[eax+60h]
    movzx eax,byte ptr[eax+0BCh]
    mov dword ptr[esi+8],eax
    ;-----------------
    mov eax, dword ptr[ebx+18h]
    mov eax, dword ptr[eax+40h]
    mov dword ptr[esi+0Ch],eax
    ;----------------
    mov eax, dword ptr[ebx+18h]
    mov eax, dword ptr[eax+44h]
    mov dword ptr[esi+10h],eax
    ;----------------
    mov eax,esi
	ret
get_debuginfo32 endp
;==============================================================
get_InInitializationOrderModuleListFlink proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+30h]
    ;-------------------------
    mov eax,dword ptr[eax+0Ch]
    mov eax,dword ptr[eax+1Ch] ;EAX is the address of PEB-> Ldr.InInitializationOrderModuleList.Flink
    
	ret
get_InInitializationOrderModuleListFlink endp
;=======================================================
;Input DllName in Unicode String!
;=======================================================
get_PEBFunction32 proc uses ebx esi edi dllName:DWORD,lpFunctionName:DWORD
    LOCAL lens:DWORD
    
    ;---------------------------------------
    ;get the string length of the target dll
    ;---------------------------------------
    
    push dllName
    pop edi
    ;-------------
	mov ecx, 64h
	xor eax,eax
	repne scasw
	mov ecx,edi
	sub ecx, dllName
	shr ecx,1
	mov lens,ecx
	;-------------
    call get_InInitializationOrderModuleListFlink
    ;------------------
    mov ebx,eax
@@:
    mov eax,dword ptr[ebx+20h] ; EAX contains the address of the module’s name in the form of its Unicode string.
    ;-------------------
    or eax,eax
    je @@Ret
    ;-------------------
    mov ecx,lens
    mov edi,eax
    mov esi,dllName
    ;-------------------
    repe cmpsw
    ;-------------------
    jne @@Next
    
    ;-------------------
    ;GET DLL BASE ADDRESS
    ;--------------------
    
    mov eax,dword ptr[ebx+8]
    ;--------------------
    push lpFunctionName
    push eax
    ;--------------------
    call get_ProcAddr32
    ;--------------------
    jmp @@Ret
@@Next:
    ;-------------------
    mov ebx,dword ptr[ebx]
    or ebx,ebx
    jne @B
    
@@Ret:
	ret
get_PEBFunction32 endp
;=====================================================================
get_ProcAddressWithHash32 proc uses ebx esi edi hash:DWORD
    LOCAL pModuleBase:DWORD
    LOCAL BaseDllName:DWORD
    LOCAL ExportDirRVA:DWORD
    LOCAL pExportDir:DWORD
    LOCAL pDataTableEntry:DWORD
    LOCAL i:DWORD
    ;------------------
    call get_pebLdrData32
    ;------------------
    mov esi,dword ptr[eax+0Ch] ;InMemoryOrderLinks DWORD +C

@@While:
    mov eax, dword ptr[esi+18h] ;DllBase
    or eax,eax
    je @@Ret
    ;-------------------
    mov pModuleBase,eax
    mov edx,eax                    ;DllBase-> DOS Hdr
    ;-------------------
    xor ebx,ebx                    ;Hash
    mov ecx,dword ptr[esi+2Ch]     ;BaseDllName
    mov edi,dword ptr[esi+30h]     ;BaseDllName Unicode struct
    ;-------------------
    mov esi,dword ptr[esi]         ;Next pDataTableEntry->InLoadOrderLinks.Flink
    mov pDataTableEntry,esi
    ;-------------------
    mov eax,dword ptr[edx+3Ch]     ;pointer to PE HDR
    mov eax,dword ptr[eax+edx+78h] ;ExportDir
    mov ExportDirRVA,eax
    ;-------------------
    or eax,eax
    je @@While
    
    ;-------------------------
    ;Calculate the module hash
    ;-------------------------
    
    mov eax,edi                    ;UnicodeString DllName
    xor edx,edx                    ;edx -> index to string
    shrd ecx,eax,10h               ;get lens of string
    movzx esi,cx
    test esi,esi                   ;esi->lens
    je @@L0                
    ;------------------------
@@For:
    movsx eax,byte ptr[edi+edx]
    ror ebx,0Dh
    add eax,ebx
    cmp byte ptr[edi+edx],61h       ;if char >= 'a' -> 'A'
    lea ebx,dword ptr[eax-20h]
    cmovl ebx,eax
    inc edx
    cmp edx,esi
    jb @@For
    
@@L0:
    mov edx,pModuleBase
    mov eax,ExportDirRVA
    add eax,edx
    mov pExportDir,eax
    ;-------------------
    ;We'll assume the function we are matching isn't the very first or last for safety
    ;-------------------
    
    mov edi,dword ptr[eax+18h]  ;NumberOfNames
    dec edi
    mov eax,dword ptr[eax+20h]  ;AddressOfNames 
    ;-------------------
    ;get last address
    ;-------------------
    lea ecx,dword ptr[eax+edi*4]
    add ecx,edx
    ;-------------------
    cmp edi,1
    jle @@While
    ;-------------------
@@For2:
    mov esi,dword ptr[ecx]      ;NameRVA
    xor eax,eax                 ;Function Hash
    add esi,edx                 ;FunctionName
    ;-------------------
    sub ecx,4                   ;dec address ,we will iterate upward
    mov i,ecx
    ;-------------------
    ;hash
    ;-------------------
@@L1:
    mov dl,byte ptr[esi]
    lea esi,dword ptr[esi+1]   ;next char
    ror eax,0Dh
    movsx ecx,dl
    add eax,ecx
    test dl,dl
    jne @@L1
    ;------------------
    mov edx,pModuleBase
    
    ;------------------
    ;Suming Hashes
    ;------------------
    
    add eax,ebx
    cmp eax,hash
    je @@GetAddress
    ;------------------
    mov ecx,i
    dec edi                        ;NumberOfNames
    cmp edi,1
    ja @@For2
    ;------------------
    mov esi,pDataTableEntry
    jmp @@While
@@GetAddress:
    mov esi,pExportDir
    mov eax,dword ptr[esi+24h]    ;*AddressOfNameOrdinals RVA
    lea eax,dword ptr[eax+edi*2]
    movzx ecx,word ptr[eax+edx]   ;ordinal
    mov eax,dword ptr[esi+1Ch]    ;*AddressOfFunctions
    lea eax,dword ptr[eax+ecx*4]
    mov eax,dword ptr[eax+edx]
    add eax,edx
    
@@Ret:
	ret
get_ProcAddressWithHash32 endp
;=====================================================================
;Returns full path including module name in unicode string
;=====================================================================
get_ModuleFullPath32 proc uses ebx esi edi

    ;-----------------------
    call get_pebLdrData32
    ;-----------------------
    push eax
    ;-----------------------
    call get_InMemoryOrderModuleListFlink
    ;-----------------------
    mov eax,dword ptr[eax+20h] ; EAX contains the address of the module’s path in the form of its Unicode string.
    ;-------------------
    
	ret
get_ModuleFullPath32 endp
;=====================================================================
get_ModuleEntryPoint32 proc uses ebx esi edi

    ;-----------------------
    call get_pebLdrData32
    ;-----------------------
    push eax
    ;-----------------------
    call get_InMemoryOrderModuleListFlink
    ;-----------------------
    mov eax,dword ptr[eax+14h]
    ;-------------------

	ret
get_ModuleEntryPoint32 endp
;=====================================================================
get_ModuleImageBase32 proc uses ebx esi edi

    call get_pebLdrData32
    ;-----------------------
    push eax
    ;-----------------------
    call get_InMemoryOrderModuleListFlink
    ;-----------------------
    mov eax,dword ptr[eax+10h]
    ;-------------------

	ret
get_ModuleImageBase32 endp
;=====================================================================
get_ImageBase32 proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    ;-----------------------
    mov eax,dword ptr[eax+8]
	ret
get_ImageBase32 endp
;=====================================================================
get_ProcessCurDir32 proc uses ebx esi edi

    call get_pebBaseAddress32
    ;------------------------
    push eax
    ;------------------------
    call get_ProcessParameters32
    ;------------------------
    mov eax,dword ptr[eax+28h]

	ret
get_ProcessCurDir32 endp
;=====================================================================
is_BeingDebugged proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr [eax+30h]
    movzx eax,byte ptr[eax+2]

	ret
is_BeingDebugged endp
;=====================================================================
is_NtGlobalFlag proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+68h]
    test eax,70h
    setne al
    
    ;mov eax,dword ptr fs:[18h]
    ;sub eax,2000h
    ;mov eax,dword ptr[eax+60h]
    ;movzx eax,byte ptr[eax+0BCh]
    ;test eax,70h
    ;setne al
    
	ret
is_NtGlobalFlag endp
;=====================================================================
get_ProcessHeap proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+18h]

	ret
get_ProcessHeap endp
;=====================================================================
;if eax > 2 we are debugging
;=====================================================================
get_ProcessHeapFlags proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+18h]
    mov eax,dword ptr[eax+40h]
    
	ret
get_ProcessHeapFlags endp
;=====================================================================
;if EAX > 0 we are debugging
;=====================================================================
get_ProcessHeapForceFlags proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+18h]
    mov eax,dword ptr[eax+44h]
    
	ret
get_ProcessHeapForceFlags endp
;=====================================================================
get_ProcessId proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+20h]
	ret
get_ProcessId endp
;=====================================================================
get_ProcessThreadId proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[18h]
    mov eax,dword ptr[eax+24h]
	ret
get_ProcessThreadId endp
;=====================================================================
get_LastErrorValue proc uses ebx esi edi

    assume fs:nothing
    mov eax,dword ptr fs:[34h]
	ret
get_LastErrorValue endp
;=====================================================================
get_ProcAddr32 proc uses ebx esi edi base:DWORD,procName:DWORD
   
    ;---------------------------------------
    ;get the string length of the target Api
    ;---------------------------------------
    
    push procName
    pop edi
    ;-------------
	mov ecx, MAX_API_STRING_LENGTH
	xor al,al
	repne scasb
	mov ecx,edi
	sub ecx, procName
	;-------------
	push base
	pop esi
	add esi,dword ptr[esi+3Ch]
	
	;-----------------------
	; trace the export table
	;-----------------------
	
	mov edx,dword ptr[esi+78h]    ;Export table RVA
	
	;-----------------------
	;Get Export Table Address
	;-----------------------
	
	add edx,base                  ;edx -> ExportTable
	mov ebx,dword ptr[edx+20h]    ;ebx -> RVA of Array Functions Names
	add ebx,base                  ;ebx -> Array of Names
	
	;------------------------
	;Loop array
	;------------------------
	
	xor eax,eax
@@For:
    mov edi,dword ptr[ebx+eax*4]  ;RVA of name string
    add edi,base
    ;------------------------
    push procName
    pop esi
    ;------------------------
    push ecx                      ;save string length
    ;------------------------
    repe cmpsb
    ;------------------------
    pop ecx
    je @@Done
    ;------------------------
@@Next:
    inc eax
    cmp eax,dword ptr[edx+18h]    ;+18  (24) DWORD 	NumberOfNames
    jl @@For
@@Done:
    cmp eax,dword ptr[edx+18h]    ; did we found ?
    jb @F
    ;------------------------
    xor eax,eax
    jmp @@Ret
@@:
    ;------------------------------
    ;find the corresponding Ordinal 
    ;eax -> index to the array
    ;------------------------------
    
    mov esi,dword ptr[edx+24h]    ;+24  (36) DWORD 	*AddressOfNameOrdinals
    add esi,base                  ;esi -> Address to Array
    ;------------------------
    movzx ecx,word ptr[esi+eax*2] ; ordinal    
    ;------------------------
    mov esi,dword ptr[edx+1Ch]
    add esi,base                  ;*AddressOfFunctions
    ;-------------------------
    mov eax,dword ptr[esi+ecx*4]
    add eax,base

@@Ret:
	ret
get_ProcAddr32 endp
;===================================================
get_kernel32base proc

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov eax,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    ;----------------------
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+12*2],dl  ;kernel32.dll->lens 12
    jne @@Module
    ;----------------------

	ret
get_kernel32base endp
;===================================================
get_ntdll32base proc

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov eax,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    ;----------------------
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+9*2],dl  ;ntdll.dll->lens 9
    jne @@Module
    ;----------------------

	ret
get_ntdll32base endp
;===================================================
get_kernelbase32base proc

    assume fs:nothing
    mov eax,dword ptr fs:[30h]
    mov eax,dword ptr[eax+0Ch] ;PEB->Ldr
    mov esi,dword ptr[eax+1Ch] ;PEB->Ldr.InInitOrder
    xor edx,edx
@@Module:
    mov eax,dword ptr[esi+8]   ;base address
    mov edi,dword ptr[esi+20h] ;unicode str
    ;----------------------
    mov esi,dword ptr[esi]
    cmp byte ptr[edi+14*2],dl  ;kernelbase.dll->lens 14
    jne @@Module
    ;----------------------

	ret
get_kernelbase32base endp
;===================================================