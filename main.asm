include main.inc
.code
start:
     call main
     ;----------
     push eax
     call ExitProcess
;==============================
main proc
    
    printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")	
    printf("\n   MapInjector v1,0 by Tempesta - Manual DLL injection\n")
    printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    
    fn initializer
    ;-------------------
    or eax,eax
    je @@Ret
    ;-------------------
    fn map_injector,&szTargetW,&injectDll
    ;-------------------
    or eax,eax
    jne @F
    ;---------------
    printf("Failed to inject DLL\n")
    ;---------------
    jmp @@Ret
@@:
    ;---------------
    printf("Dll injected!\n")
    ;-------------------
@@Ret:
    inkey
    xor eax,eax
	ret
main endp     
end start