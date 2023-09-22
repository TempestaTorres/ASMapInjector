
initializer proto

.data
szTarget  db 128 dup(0)
szTargetW dw 128 dup(0)
injectDll db 128 dup(0)

.code
initializer proc uses ebx esi edi
    LOCAL result:DWORD
    
    and result,0
    ;---------------
    fn GetCL,1,offset szTarget
    ;---------------
    cmp eax,1
    je @F
    ;--------------------------------
    printf("\nUsage:injector.exe [exe_path] [dll_path]\n")
    ;--------------------------------
    jmp @@Ret
@@:
    fn GetCL,2,offset injectDll
    ;---------------
    cmp eax,1
    je @F
    ;--------------------------------
    printf("\nUsage:injector.exe [exe_path] [dll_path]\n")
    ;--------------------------------
    jmp @@Ret
@@:
    fn  MultiByteToWideChar,CP_ACP,MB_PRECOMPOSED,offset szTarget,-1,offset szTargetW,256
    ;------------------------------
    mov result,1
@@Ret:
    mov eax,result
	ret
initializer endp