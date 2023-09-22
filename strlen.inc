
.code
strlen proc

   mov eax,dword ptr[esp+4]
   lea edx,dword ptr[eax+3]
   push ebp
   push edi
   mov ebp,80808080h
@@L2:
   mov edi,dword ptr[eax]
   add eax,4
   lea ecx,dword ptr[edi-1010101h]
   not edi
   and ecx,edi
   and ecx,ebp
   jne @@L0
   ;-------------
   mov edi,dword ptr[eax]
   add eax,4
   lea ecx,dword ptr[edi-1010101h]
   not edi
   and ecx,edi
   and ecx,ebp
   jne @@L0
   ;--------------
   mov edi,dword ptr[eax]
   add eax,4
   lea ecx,dword ptr[edi-1010101h]
   not edi
   and ecx,edi
   and ecx,ebp
   jne @@L0
   ;--------------
   mov edi,dword ptr[eax]
   add eax,4
   lea ecx,dword ptr[edi-1010101h]
   not edi
   and ecx,edi
   and ecx,ebp
   je @@L2
   ;---------------
@@L0:
   test ecx,8080h
   jne @@L1
   ;---------------
   shr ecx,10h
   add eax,2
@@L1:
   shl cl,1
   sbb eax,edx
   pop edi
   pop ebp

	ret 4
strlen endp  