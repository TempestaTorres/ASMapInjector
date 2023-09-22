include \masm32\include\kernl32p.inc
includelib \masm32\lib\kernl32p.lib

include \masm32\include\psapi.inc
includelib \masm32\lib\psapi.lib

PROCESSENTRY32W STRUCT
    
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ProcessID       DWORD ?
    th32DefaultHeapID   DWORD ?
    th32ModuleID        DWORD ?
    cntThreads          DWORD ?
    th32ParentProcessID DWORD ?
    pcPriClassBase      DWORD ?
    dwFlags             DWORD ?
    szExeFile           dw MAX_PATH dup(?)
    
PROCESSENTRY32W ENDS

MODULEENTRY32W STRUCT
    
    dwSize          DWORD ?
    th32ModuleID    DWORD ?
    th32ProcessID   DWORD ?
    GlblcntUsage    DWORD ?
    ProccntUsage    DWORD ?
    modBaseAddr     DWORD ?
    modBaseSize     DWORD ?
    hModule         DWORD ?
    szModule        dw MAX_MODULE_NAME32+1 dup(?)
    szExePath       dw MAX_PATH dup(?)
    
MODULEENTRY32W ENDS

PROCESSINFO struct

    th32ProcessID   DWORD ?
    szProcessName   dw 32 dup(?)

PROCESSINFO ends

get_processID          proto :DWORD
get_process_threadID   proto :DWORD
open_process           proto :DWORD
getLoadLibraryAddress  proto
get_module_baseaddress proto :DWORD,:DWORD
get_processes_count    proto
get_processes_info     proto

.data
kerneldll   db "kernel32.dll",0
loadlibrary db "LoadLibraryA",0

.code
;===========================================================
;returns count of processes
;===========================================================
get_processes_count proc uses ebx esi edi
    LOCAL buffer[1024]:DWORD
    LOCAL cbNeeded:DWORD
    
    lea edx,cbNeeded
    ;------------------
    invoke EnumProcesses,addr buffer,sizeof buffer,edx
    ;------------------
    or eax,eax
    je @@Ret
    ;------------------
    mov eax,cbNeeded
    shr eax,2
@@Ret:
	ret
get_processes_count endp
;===========================================================
get_processes_info proc uses ebx esi edi
    LOCAL processEntry:PROCESSENTRY32W
    LOCAL snapshot:DWORD
    LOCAL pi:DWORD
    
    mov processEntry.dwSize,sizeof PROCESSENTRY32W
    ;---------------------
    invoke CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS, 0
    ;------------------------------
    mov snapshot,eax
    cmp eax,INVALID_HANDLE_VALUE
    je @@Ret
    ;------------------------------
    invoke Process32FirstW,snapshot, addr processEntry
    ;------------------------------
    or eax,eax
    je @@Done
    ;------------------------------
    call get_processes_count
    ;---------------------
    inc eax
    mov ecx,sizeof PROCESSINFO
    imul eax,ecx
    ;------------------------------
    invoke GlobalAlloc,GPTR,eax
    ;------------------------------
    mov pi,eax
    mov esi,eax
@@Do:
    ;------------------------------
    mov eax,processEntry.th32ProcessID
    mov dword ptr[esi],eax
    ;------------------------------
    lea eax,processEntry.szExeFile
    push eax
    lea eax,dword ptr[esi+4]
    push eax
    ;------------------------------
    call lstrcpyW
    ;------------------------------
    add esi,sizeof PROCESSINFO
    ;-------------------------------
    invoke Process32NextW,snapshot,addr processEntry
    ;-------------------------------
    or eax,eax
    jne @@Do
@@Done:

    invoke CloseHandle,snapshot
    ;------------------------------
    push pi
    pop eax
@@Ret:
	ret
get_processes_info endp
;===========================================================
get_processID proc uses ebx esi edi lpszTarget:DWORD
    LOCAL processEntry:PROCESSENTRY32W
    LOCAL snapshot:DWORD
    LOCAL processID:DWORD
    LOCAL lens:DWORD
    
    xor eax,eax
    mov edi,lpszTarget
    repne scasw
    sub edi,lpszTarget
    shr edi,1
    dec edi
    mov lens,edi
    ;------------------------------
    and processID,0
    mov processEntry.dwSize,sizeof PROCESSENTRY32W
    ;------------------
    invoke CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS, 0
    ;------------------------------
    mov snapshot,eax
    cmp eax,INVALID_HANDLE_VALUE
    je @@Ret
    ;------------------------------
    invoke Process32FirstW,snapshot, addr processEntry
    ;------------------------------
    or eax,eax
    je @@L1
    ;------------------------------
@@Do:
    lea esi,processEntry.szExeFile
    mov edi,lpszTarget
    mov ecx,lens
    repe cmpsw
    jne @@Next
    ;------------------------------
    mov eax,processEntry.th32ProcessID
    mov processID,eax
    jmp @@L1
 
@@Next:
    invoke Process32NextW,snapshot,addr processEntry
    ;-------------------------------
    or eax,eax
    jne @@Do
@@L1:
    invoke CloseHandle,snapshot
    ;------------------------------
	push processID
	pop eax
	
@@Ret:
	ret
get_processID endp
;===================================================================
get_module_baseaddress proc uses ebx esi edi processId:DWORD,moduleName:DWORD
    LOCAL hModuleSnapshot:DWORD
    LOCAL moduleEntry:MODULEENTRY32W
    LOCAL modBaseAddr:DWORD
    
    and modBaseAddr,0
    mov moduleEntry.dwSize, sizeof MODULEENTRY32W
    ;--------------------------
    invoke CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,processId
    ;--------------------------
    mov hModuleSnapshot,eax
    cmp eax,INVALID_HANDLE_VALUE
    je @@Ret
    ;--------------------------
    invoke Module32FirstW,hModuleSnapshot,addr moduleEntry
    ;--------------------------
    or eax,eax
    je @@Done
    ;--------------------------
@@Do:
    lea eax,moduleEntry.szModule
    push eax
    push moduleName
    ;------------------------------
    call lstrcmpW
    ;------------------------------
    or eax,eax
    jne @@Next
    ;------------------------------
    mov eax,moduleEntry.modBaseAddr
    mov modBaseAddr,eax
    jmp @@Done 
      
@@Next:
    invoke Module32NextW,hModuleSnapshot,addr moduleEntry
    ;--------------------------
    or eax,eax
    jne @@Do
           
@@Done:
    invoke CloseHandle,hModuleSnapshot
    
@@Ret:
    push modBaseAddr
    pop eax
	ret
get_module_baseaddress endp
;===================================================================
get_process_threadID proc uses ebx esi edi processId:DWORD
    LOCAL snapshot:DWORD
    LOCAL threadID:DWORD
    LOCAL threadEntry:THREADENTRY32
    
    and threadID,0
    
    invoke CreateToolhelp32Snapshot,TH32CS_SNAPTHREAD, 0
    ;------------------------------
    mov snapshot,eax
    cmp eax,0FFFFFFFFh
    je @@Ret
    ;-------------------------------
    
    mov threadEntry.dwSize,sizeof(THREADENTRY32)
    ;-------------------------------
    invoke Thread32First,snapshot, addr threadEntry
    ;-------------------------------
    or eax,eax
    je @@L1
@@Do:
    mov eax,threadEntry.th32OwnerProcessID
    mov edx,processId
    cmp eax,edx
    jne @@Next
    ;------------------------------
    mov eax,threadEntry.th32ThreadID
    mov threadID,eax
    jmp @@L1
    
@@Next:
    invoke Thread32Next,snapshot, addr threadEntry
    ;------------------------------
    or eax,eax
    jne @@Do
    
@@L1:
    invoke CloseHandle,snapshot
@@Ret:
    push threadID
    pop eax
	ret
get_process_threadID endp
;===================================================================
open_process proc uses ebx esi edi processID:DWORD

    invoke OpenProcess,PROCESS_ALL_ACCESS, FALSE, processID

	ret
open_process endp
;===================================================================
getLoadLibraryAddress proc

    invoke GetModuleHandle,offset kerneldll
    ;-----------------
    or eax,eax
    je @@Ret
    ;-----------------
    invoke GetProcAddress,eax,offset loadlibrary        
 
@@Ret:
	ret
getLoadLibraryAddress endp