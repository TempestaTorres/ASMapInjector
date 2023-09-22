include \masm32\include\advapi32.inc
includelib \masm32\lib\advapi32.lib
;===================================================================================================
;Opening another process with write access is submitted to restrictions. One protection is Mandatory
;Integrity Control (MIC). MIC is a protection method to control access to objects based on their
;Integrity level". There are 4 integrity levels:

;Low Level for process which are restricted to access most of the system (for example Internet
;explorer)
;• Medium Level is the default for any process started by unprivileged users and also
;administrator users if UAC is enabled.
;• High level is for process running with administrator privileges
;• System level are ran by SYSTEM users, generally the level of system services and process
;requiring the highest protection.

; A normal process cannot inject code into a process protected with these mechanisms.

;===================================================================================================
SE_PRIVILEGE_ENABLED equ 2


.code
magic_enable_privilege proc uses ebx esi edi
    LOCAL priv:TOKEN_PRIVILEGES
    LOCAL hToken:DWORD
    
    lea ebx,priv
    ;----------------------
    and dword ptr[ebx],0
    and dword ptr[ebx+4],0
    and dword ptr[ebx+8],0
    and dword ptr[ebx+0Ch],0
    ;-----------------------
    invoke GetCurrentProcess
    ;-----------------------
    mov edx,eax
    ;------------------------
    invoke OpenProcessToken,edx,TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,addr hToken
    ;------------------------
    or eax,eax
    je @@Ret
    ;------------------------
    mov dword ptr[ebx],1                     ;PrivilegeCount
    lea eax,dword ptr[ebx+8]
    mov dword ptr[eax],SE_PRIVILEGE_ENABLED  ;priv.Privileges[0].Attributes
    ;------------------------
    mov eax,ebx
    add eax,4                                ;&priv.Privileges[0].Luid
    ;------------------------
    invoke LookupPrivilegeValue,NULL,CADD("SeDebugPrivilege"),eax
    ;------------------------
    or eax,eax
    je @@Ret
    ;------------------------
    invoke AdjustTokenPrivileges,hToken,FALSE,ebx,0,NULL,0
    ;--------------
    invoke CloseHandle,hToken
@@Ret:
	ret
magic_enable_privilege endp
;======================================================