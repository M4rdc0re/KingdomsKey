.data
	wSysC DWORD 0h

.code 
	ConfS PROC
		xor eax, eax
		nop
		mov wSysC, eax
		nop
		mov eax, ecx
		nop
		mov wSysC, eax
		ret
	ConfS ENDP

	RunSys PROC
		xor r10, r10
		nop
		mov rax, rcx
		nop
		mov r10, rax
		nop
		mov eax, wSysC
		nop
		jmp Go
		xor rcx, rcx
		nop
		xor eax, eax
	Go:
		syscall
		ret
	RunSys ENDP
end