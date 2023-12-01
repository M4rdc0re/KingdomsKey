.data
	wSystemCall DWORD 0h

.code 
	ConfS PROC
		xor eax, eax
		mov wSystemCall, eax
		mov eax, ecx
		mov wSystemCall, eax
		ret
	ConfS ENDP

	RunSys PROC
		xor r10, r10
		mov rax, rcx
		mov r10, rax
		mov eax, wSystemCall
		jmp Run
		xor eax, eax
		xor rcx, rcx
	Run:
		syscall
		xor r10, r10
		ret
	RunSys ENDP
end