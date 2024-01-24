#include <Windows.h>
#include "Common.h"
#include "Debug.h"

HMODULE GetModuleHandleH(DWORD dwModuleHash) {
	if (dwModuleHash == NULL)
		return NULL;

	PPEB					pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {

			if (pDte->FullDllName.Length < MAX_PATH - 1) {
				CHAR DllName[MAX_PATH] = { 0 };
				DWORD i = 0;
				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
					if ((CHAR)pDte->FullDllName.Buffer[i] >= 'a' && (CHAR)pDte->FullDllName.Buffer[i] <= 'z')
						DllName[i] = (CHAR)pDte->FullDllName.Buffer[i] - 'a' + 'A';
					else
						DllName[i] = (CHAR)pDte->FullDllName.Buffer[i];
					i++;
				}
				DllName[i] = '\0';
				if (HASHA(DllName) == dwModuleHash) {
					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				}
			}
		}
		else {
			break;
		}

		pDte = (PLDR_DATA_TABLE_ENTRY) * (DWORD64*)(pDte);
	}

#ifdef DEBUG
	PRINTA("[!] GetModuleHandleH Failed To Retrieve The Handle Of Module Of Hash Value : 0x%0.8X \n", dwModuleHash);
#endif // DEBUG

	return NULL;
}

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash) {

	if (hModule == NULL || dwApiHash == NULL)
		return NULL;

	HMODULE						hModule2 = NULL;
	UINT64						DllBaseAddress = (UINT64)hModule;
	PIMAGE_NT_HEADERS			NtHdr = (PIMAGE_NT_HEADERS)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
	PIMAGE_DATA_DIRECTORY		pDataDir = (PIMAGE_DATA_DIRECTORY)&NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY		ExportTable = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pDataDir->VirtualAddress);

	UINT64	FunctionNameAddressArray = (DllBaseAddress + ExportTable->AddressOfNames);
	UINT64	FunctionAddressArray = (DllBaseAddress + ExportTable->AddressOfFunctions);
	UINT64	FunctionOrdinalAddressArray = (DllBaseAddress + ExportTable->AddressOfNameOrdinals);
	UINT64	pFunctionAddress = 0x00;
	DWORD	dwCounter = ExportTable->NumberOfNames;


	while (dwCounter--) {
		PCHAR FunctionName = (PCHAR)(DllBaseAddress + *(DWORD*)(FunctionNameAddressArray));

		if (HASHA(FunctionName) == dwApiHash) {
			FunctionAddressArray += (*(WORD*)(FunctionOrdinalAddressArray) * sizeof(DWORD));
			pFunctionAddress = (UINT64)(DllBaseAddress + *(DWORD*)(FunctionAddressArray));
			if (pDataDir->VirtualAddress <= *(DWORD*)(FunctionAddressArray) && (pDataDir->VirtualAddress + pDataDir->Size) >= *(DWORD*)(FunctionAddressArray)) {
				CHAR Library[MAX_PATH] = { 0 };
				CHAR Function[MAX_PATH] = { 0 };
				UINT32 Index = _CopyDotStr((PCHAR)pFunctionAddress);
				if (Index == 0) {
					return NULL;
				}
				_memcpy((PVOID)Library, (PVOID)pFunctionAddress, Index);
				_memcpy((PVOID)Function, (PVOID)((ULONG_PTR)pFunctionAddress + Index + 1), _StrlenA((LPCSTR)((ULONG_PTR)pFunctionAddress + Index + 1)));
				if ((hModule2 = LoadLibraryH(Library)) != NULL) {
					pFunctionAddress = (UINT64)GetProcAddressH(hModule2, HASHA(Function));
				}
			}
			break;
		}
		FunctionNameAddressArray += sizeof(DWORD);
		FunctionOrdinalAddressArray += sizeof(WORD);
	}
	return (FARPROC)pFunctionAddress;
}

HMODULE LoadLibraryH(LPSTR DllName) {

	UNICODE_STRING	Ustr = { 0 };
	WCHAR			wDllName[MAX_PATH] = { 0 };
	NTSTATUS		STATUS = 0x00;
	HMODULE			hModule = NULL;

	_CharToWchar(wDllName, DllName, _StrlenA(DllName));

	USHORT DestSize = _StrlenW(wDllName) * sizeof(WCHAR);
	Ustr.Length = DestSize;
	Ustr.MaximumLength = DestSize + sizeof(WCHAR);
	Ustr.Buffer = wDllName;


	fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)GetProcAddressH(GetModuleHandleH(NTDLLDLL_JOAA), LdrLoadDll_JOAA);
	if (pLdrLoadDll != NULL && (STATUS = pLdrLoadDll(NULL, 0, &Ustr, &hModule)) == 0x0) {
		return hModule;
	}

#ifdef DEBUG
	PRINTW(L"[!] LdrLoadDll Faild To Load \"%s\" 0x%0.8X \n", wDllName, STATUS);
#endif // DEBUG

	return NULL;
}