#include <Windows.h>
#include <stdio.h>

#define STR "_JOAA"
#define INITIAL_SEED 8

UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


UINT32 HashStringJenkinsOneAtATime32BitW(PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

int main() {

	printf("#define %s%s \t0x%0.8X \n", "NtCreateSection", STR, HashStringJenkinsOneAtATime32BitA("NtCreateSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtMapViewOfSection", STR, HashStringJenkinsOneAtATime32BitA("NtMapViewOfSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtUnmapViewOfSection", STR, HashStringJenkinsOneAtATime32BitA("NtUnmapViewOfSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtClose", STR, HashStringJenkinsOneAtATime32BitA("NtClose"));
	printf("#define %s%s \t0x%0.8X \n", "NtCreateThreadEx", STR, HashStringJenkinsOneAtATime32BitA("NtCreateThreadEx"));
	printf("#define %s%s \t0x%0.8X \n", "NtWaitForSingleObject", STR, HashStringJenkinsOneAtATime32BitA("NtWaitForSingleObject"));
	printf("#define %s%s \t0x%0.8X \n", "NtQuerySystemInformation", STR, HashStringJenkinsOneAtATime32BitA("NtQuerySystemInformation"));
	printf("#define %s%s \t0x%0.8X \n", "NtDelayExecution", STR, HashStringJenkinsOneAtATime32BitA("NtDelayExecution"));
	printf("#define %s%s \t0x%0.8X \n", "CallNextHookEx", STR, HashStringJenkinsOneAtATime32BitA("CallNextHookEx"));
	printf("#define %s%s \t0x%0.8X \n", "DefWindowProcW", STR, HashStringJenkinsOneAtATime32BitA("DefWindowProcW"));
	printf("#define %s%s \t0x%0.8X \n", "GetMessageW", STR, HashStringJenkinsOneAtATime32BitA("GetMessageW"));
	printf("#define %s%s \t0x%0.8X \n", "SetWindowsHookExW", STR, HashStringJenkinsOneAtATime32BitA("SetWindowsHookExW"));
	printf("#define %s%s \t0x%0.8X \n", "UnhookWindowsHookEx", STR, HashStringJenkinsOneAtATime32BitA("UnhookWindowsHookEx"));
	printf("#define %s%s \t0x%0.8X \n", "GetModuleFileNameW", STR, HashStringJenkinsOneAtATime32BitA("GetModuleFileNameW"));
	printf("#define %s%s \t0x%0.8X \n", "CreateFileW", STR, HashStringJenkinsOneAtATime32BitA("CreateFileW"));
	printf("#define %s%s \t0x%0.8X \n", "GetTickCount64", STR, HashStringJenkinsOneAtATime32BitA("GetTickCount64"));
	printf("#define %s%s \t0x%0.8X \n", "OpenProcess", STR, HashStringJenkinsOneAtATime32BitA("OpenProcess"));
	printf("#define %s%s \t0x%0.8X \n", "SetFileInformationByHandle", STR, HashStringJenkinsOneAtATime32BitA("SetFileInformationByHandle"));
	printf("#define %s%s \t0x%0.8X \n", "SystemFunction032", STR, HashStringJenkinsOneAtATime32BitA("SystemFunction032"));
	printf("#define %s%s \t0x%0.8X \n", "KERNEL32DLL", STR, HashStringJenkinsOneAtATime32BitA("KERNEL32.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "USER32DLL", STR, HashStringJenkinsOneAtATime32BitA("USER32.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "NTDLLDLL", STR, HashStringJenkinsOneAtATime32BitA("NTDLL.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "LdrLoadDll", STR, HashStringJenkinsOneAtATime32BitA("LdrLoadDll"));
	printf("#define %s%s \t0x%0.8X \n", "Notepad", STR, HashStringJenkinsOneAtATime32BitW(L"Notepad.exe"));
	getchar();

	return 0;
}