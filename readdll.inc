
read_dll proto :DWORD

.code
read_dll proc uses ebx esi edi dllPath:DWORD
    LOCAL result:DWORD
    LOCAL hFile:DWORD
    LOCAL bRead:DWORD
    
    and result,0
    ;-----------------------------
    printf("\nOpening the DLL.\n")
    ;-----------------------------
    fn CreateFile,dllPath, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    ;-----------------------------
    cmp eax,-1
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to open the DLL (%d)\n",eax)
    ;-----------------------------
    jmp @@Ret
    ;-----------------------------
@@:
    mov hFile,eax
    ;-----------------------------
    fn GetFileSize,eax, NULL
    ;-----------------------------
    mov ebx,eax
    ;-----------------------------
    fn VirtualAlloc,NULL, ebx, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    ;-----------------------------
    or eax,eax
    jne @F
    ;-----------------------------	
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to allocate memory for DLL data (%d)\n",eax)		
    ;-----------------------------
    jmp @@Close
@@:
    ;-----------------------------
    ;         Read the DLL
    ;-----------------------------
    
    mov edi,eax
    ;-----------------------------
    fn ReadFile,hFile, edi, ebx, addr bRead, NULL
    ;-----------------------------
    or eax,eax
    jne @F
    ;-----------------------------
    call GetLastError
    ;-----------------------------
    printf("\nError: Unable to read the DLL (%d)\n",eax)
    ;-----------------------------	
    fn VirtualFree, edi, 0, MEM_RELEASE		
    ;-----------------------------
@@:
    mov result,edi  
@@Close:
    fn CloseHandle,hFile
@@Ret:
    mov eax,result
	ret
read_dll endp