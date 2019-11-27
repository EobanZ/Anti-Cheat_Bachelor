#include "stdafx.h"
#include "Utils.h"
#include <stdlib.h>
#include <TlHelp32.h>


uintptr_t Utils::getMyBaseAddress()
{
	return (uintptr_t)GetModuleHandle(NULL);
}

//Trampolin???  Aus Game Hacking buch schreiben und vergleichen. TESTEN WAS DIE MACHT
PVOID Utils::hookFunc(BYTE * src, const BYTE * dst, const int len)
{
	BYTE* jmp = (BYTE*)malloc(len + 5); //allocate memory 

	DWORD oldProt;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &oldProt);

	memcpy(jmp, src, len); //Copy the original bytes into the allocated memory
	jmp += len; //goto first byte after the injected code

	jmp[0] = 0xE9; //place a jmp instruction
	
	*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5; //calculate relative adress from trampoline to orig fuction +5

	src[0] = 0xE9; //
	*(DWORD*)(jmp + 1) = (DWORD)(dst - src) - 5;

	VirtualProtect(src, len, oldProt, &oldProt);

	//adress to trampoline
	return (jmp - len);
}

BOOL dataCompare(const BYTE* data, const BYTE* pattern, const char* mask)
{
	for (; *mask; ++mask, ++data, ++pattern)
		if (*mask == 'x' && *data != *mask)
			return FALSE;
	return (*mask) == NULL;
}

//TESTEN!!!
uintptr_t Utils::findPattern(uintptr_t address, DWORD len, BYTE * pattern, const char * mask)
{
	for (uintptr_t i = 0; i < len; ++i)
	{
		if(dataCompare((BYTE*)(address + i), pattern, mask))
			return (uintptr_t)(address + i);
	}
	return 0;
}

DWORD Utils::getThreadOwnerProcessId(DWORD threadID)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (Thread32First(hSnap, &ti))
	{
		do {
			if (threadID == ti.th32ThreadID) {
				CloseHandle(hSnap);
				return ti.th32OwnerProcessID;
			}
		} while (Thread32Next(hSnap, &ti));
	}

	CloseHandle(hSnap);
	return 0;
}


