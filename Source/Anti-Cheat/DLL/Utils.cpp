#pragma once
#include "Utils.h"
#include "ThreadEnumerator.h"
#include <string>

int chSizeOfArray(char *chArray)
{
	for (int iLength = 1; iLength < MAX_PATH; iLength++)
		if (chArray[iLength] == '*')
			return iLength;

	return 0;
}

int iSizeOfArray(int *iArray)
{
	for (int iLength = 1; iLength < MAX_PATH; iLength++)
		if (iArray[iLength] == '*')
			return iLength;

	return 0;
}

bool iFind(int *iAry, int iVal)
{

	for (int i = 0; i < 64; i++)
		if (iVal == iAry[i] && iVal != 0)
			return true;

	return false;
}

bool Utils::isSuspendedThread(DWORD dwThreadId)
{
	//Funktion funktioniert zwar, führt aber nach einiger Zeit immer zu Abstürzen. Deshalb wird isSuspendendTread2() benutzt
	CThreadEnumerator* threadEnumerator = new CThreadEnumerator(GetCurrentProcessId());
	if (threadEnumerator == nullptr) {
		delete threadEnumerator;
		return true;
	}

	auto systemThreadOwnerProcInfo = threadEnumerator->GetProcInfo();
	if (systemThreadOwnerProcInfo == nullptr) {
		delete threadEnumerator;
		return true;
	}

	auto systemThreadInfo = threadEnumerator->FindThread(systemThreadOwnerProcInfo, dwThreadId);
	if (systemThreadInfo == nullptr) {
		delete threadEnumerator;
		return true;
	}

	if (systemThreadInfo->ThreadState == Waiting && systemThreadInfo->WaitReason == Suspended) {
		delete threadEnumerator;
		return true;
	}

	delete threadEnumerator;
	return false;
}

bool Utils::isSuspendedThread2(DWORD dwThreadId)
{
	bool result = false;
	HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);

	if (threadHandle == NULL)
		result = true;

	if (SuspendThread(threadHandle) > 0) 
		result = true;

	ResumeThread(threadHandle);
	CloseHandle(threadHandle);
	return result;

}

PVOID Utils::DetourFunc(BYTE * src, const BYTE * dst, const int len)
{

	BYTE* jmp = (BYTE*)malloc(len + 5);

	DWORD dwback;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &dwback);

	memcpy(jmp, src, len);
	jmp += len;

	jmp[0] = 0xE9;
	//relative address from trampoline to origin function + 5
	*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5;

	src[0] = 0xE9;
	*(DWORD*)(src + 1) = (DWORD)(dst - src) - 5;

	VirtualProtect(src, len, dwback, NULL);

	//address to trampoline
	return(jmp - len);

}

bool Utils::IsLoadedAddress(DWORD dwAddress)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dwAddress == (DWORD)Current->DllBase)
			return true;

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}

DWORD Utils::GetThreadOwnerProcessId(DWORD dwThreadID)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (Thread32First(hSnap, &ti))
	{
		do {
			if (dwThreadID == ti.th32ThreadID) {
				CloseHandle(hSnap);
				return ti.th32OwnerProcessID;
			}
		} while (Thread32Next(hSnap, &ti));
	}

	CloseHandle(hSnap);
	return 0;
}

PVOID Utils::GetModuleAddressFromName(const wchar_t * c_wszName)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// printf("%ls -> %p\n", Current->FullDllName.Buffer, Current->DllBase);
		if (wcsstr(Current->FullDllName.Buffer, c_wszName))
			return Current->DllBase;

		CurrentEntry = CurrentEntry->Flink;
	}
	return nullptr;
}




DWORD Utils::GetProcessID(const wchar_t * ExeName)
{
	PROCESSENTRY32 ProcEntry = { 0 };
	HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (!SnapShot)
		return NULL;

	ProcEntry.dwSize = sizeof(ProcEntry);

	if (!Process32First(SnapShot, &ProcEntry))
		return NULL;

	do
	{
		if (!wcscmp(ProcEntry.szExeFile, ExeName))
		{
			CloseHandle(SnapShot);
			return ProcEntry.th32ProcessID;
		}
	} while (Process32Next(SnapShot, &ProcEntry));

	CloseHandle(SnapShot);
	return NULL;
}


bool Utils::GetModuleMD5(std::string& result)
{
	HMODULE hModule = GetModuleHandleA(NULL);
		
	PVOID pVirtualAdress = NULL;
	PVOID pCodeStart = NULL;
	PVOID pCodeEnd = NULL;
	SIZE_T dwCodeSize = 0;

	result = "HASH ERROR MODULE";

	auto pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>((DWORD)hModule);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	auto pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((DWORD)hModule + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return false;

	auto pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(pNTHeader + 1); //Stepping over the headers above to find the Section Header

	DWORD dwEntryPoint = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	UINT nSectionCount = pNTHeader->FileHeader.NumberOfSections;

	for (UINT i = 0; i < nSectionCount; i++)
	{
		// When we find a Section such that Section Start <= Entry Point < Section End, we have found the .TEXT Section
		if (pSectionHeader->VirtualAddress <= dwEntryPoint &&
			dwEntryPoint < pSectionHeader->VirtualAddress +
			pSectionHeader->Misc.VirtualSize)
			break;
		pSectionHeader++;
	}

	pCodeStart = (PVOID)((PBYTE)hModule + pSectionHeader->PointerToRawData);
	dwCodeSize = pSectionHeader->Misc.VirtualSize;

	MD5 md5;
	md5.update((const char*)pCodeStart, (unsigned int)dwCodeSize);
	md5.finalize();
	result = md5.hexdigest();
	CloseHandle(hModule);
	return true;

}

bool Utils::GetFileMD5(std::string & result)
{
	result = "HASH ERROR FILE";

	char szFileName[255];
	if (GetModuleFileNameA(NULL, szFileName, 255) == 0)
		return false;

	auto hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	auto hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	auto pBaseAdress = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (pBaseAdress == NULL)
		return false;

	auto pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>((DWORD)pBaseAdress);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	auto pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((DWORD)pBaseAdress + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return false;

	auto pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(pNTHeader + 1);

	DWORD dwEntryPoint = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	UINT nSectionCount = pNTHeader->FileHeader.NumberOfSections;

	for (UINT i = 0; i < nSectionCount; i++)
	{
		// When we find a Section such that Section Start <= Entry Point < Section End, we have found the .TEXT Section
		if (pSectionHeader->VirtualAddress <= dwEntryPoint &&
			dwEntryPoint < pSectionHeader->VirtualAddress +
			pSectionHeader->Misc.VirtualSize)
			break;
		pSectionHeader++;
	}

	auto pCodeStart = (PVOID)((PBYTE)pBaseAdress + pSectionHeader->PointerToRawData);
	auto dwCodeSize = pSectionHeader->Misc.VirtualSize;

	MD5 md5;
	md5.update((const char*)pCodeStart, (unsigned int)dwCodeSize);
	md5.finalize();
	result = md5.hexdigest();
	
	UnmapViewOfFile(pBaseAdress);
	CloseHandle(hFile);
	return true;
}





