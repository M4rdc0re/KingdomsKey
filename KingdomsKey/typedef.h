#pragma once
#include <Windows.h>
#include "Structs.h"

typedef ULONGLONG(WINAPI* fnGetTickCount64)();

typedef HANDLE(WINAPI* fnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

typedef LRESULT(WINAPI* fnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

typedef HHOOK(WINAPI* fnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

typedef BOOL(WINAPI* fnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);

typedef LRESULT(WINAPI* fnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(HHOOK hhk);

typedef DWORD(WINAPI* fnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef BOOL(WINAPI* fnSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);

typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Data,USTRING* Key);

typedef NTSTATUS(NTAPI* fnLdrLoadDll)(PWCHAR PathToFile, ULONG Flags,PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

typedef NTSTATUS(NTAPI* fnNtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
