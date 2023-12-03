.data
	wSysC DWORD 0h

.code 
	ConfS PROC
		xor eax, eax
		mov wSysC, eax
		mov eax, ecx
		mov wSysC, eax
		ret
	ConfS ENDP

	RunSys PROC
		xor r10, r10
		mov rax, rcx
		mov r10, rax
		mov eax, wSysC
		jmp Go
		xor rcx, rcx
		xor eax, eax
	Go:
		syscall
		ret
	RunSys ENDP
end