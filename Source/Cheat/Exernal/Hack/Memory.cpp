#include "pch.h"
#include "Memory.h"
#include <TlHelp32.h>


template<typename T>
T Memory::RPM(HANDLE process, DWORD_PTR adress)
{
	T value;
	ReadProcessMemory(process, adress, &value, sizeof(T), NULL);
	return value;
}

template<typename T>
void Memory::WPM(HANDLE process, DWORD_PTR adress, T value)
{
	WriteProcessMemory(process, adress, &value, sizeof(T), NULL);
}

template<typename T>
T Memory::RPM_Safe(HANDLE hProcess, DWORD_PTR address)
{

	T value;
	DWORD dwReadByteCount = 0;
	__try {
		if (!ReadProcessMemory(hProcess, address, value, sizeof(T), &dwReadByteCount))
			dwReadByteCount = 0;
	}
	__except (1) { }
	return (dwReadByteCount && dwReadByteCount == sizeof(T));

}

template<typename T>
void Memory::WPM_Safe(HANDLE hProcess, DWORD_PTR address, T value)
{
	DWORD dwWriteByteCount = 0;
	__try {
		if (!WriteProcessMemory(hProcess, address, &value, sizeof(T), &dwWriteByteCount))
			dwWriteByteCount = 0;
	}
	__except (1) { }
	return (dwWriteByteCount != 0);
}

template<typename T>
DWORD Memory::protectMemoryT(HANDLE process, DWORD_PTR adress, DWORD prot)
{
	DWORD oldProtection;
	VirtualProtectEx(process, adress, sizeof(T), prot, &oldProtection);
	return oldProtection;
}

template<int SIZE>
void Memory::writeNop(HANDLE hProcess, DWORD adress)
{
	auto oldProtection = protectMemory<BYTE[SIZE]>(adress, PAGE_EXECUTE_READWRITE);

	

	for (int i = 0; i < SIZE; ++i)
		WPM<BYTE>(hProcess, adress + i, 0x90);

	protectMemory<BYTE[SIZE]>(adress, oldProtection);

	//Testen wegen weniger WPM aufrufe -> schneller
	const BYTE* buff = new BYTE[SIZE];
	for (int i = 0; i < SIZE; ++i)
		buff[i] = 0x90;
	patch(hProcess, adress, buff, (size_t)SIZE);
	delete[] buff;


}

LPVOID Memory::Alloc(HANDLE hProcess, std::size_t size, DWORD dwProtection, LPVOID pPreferredLoc)
{
	return VirtualAllocEx(hProcess, pPreferredLoc, size, MEM_COMMIT | MEM_RESERVE, dwProtection);
}

LPVOID Memory::Commit(HANDLE hProcess, LPVOID data, std::size_t size)
{
	LPVOID AllocatedPointer = Alloc(hProcess, size);
	if (!AllocatedPointer)
		return nullptr;

	if (WriteProcessMemory(hProcess, AllocatedPointer, data, size, NULL))
		return AllocatedPointer;

	Free(hProcess, AllocatedPointer, size);
	return nullptr;
}

bool Memory::Free(HANDLE hProcess, LPVOID address, std::size_t size)
{
	return (VirtualFreeEx(hProcess, address, NULL, MEM_RELEASE) == TRUE);
}

bool Memory::readAdress(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size)
{
	SIZE_T dwReadByteCount = 0;
	if (!ReadProcessMemory(hProcess, address, buffer, size, &dwReadByteCount))
		dwReadByteCount = 0;
	return dwReadByteCount != 0;
}

bool Memory::readAdressSafe(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size)
{
	SIZE_T dwReadByteCount = 0;
	__try {
		if (!ReadProcessMemory(hProcess, address, buffer, size, &dwReadByteCount))
			dwReadByteCount = 0;
	}
	__except (1) { }
	return (dwReadByteCount && dwReadByteCount == size);
}

bool Memory::writeAdress(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size)
{
	SIZE_T dwWriteByteCount = 0;
	if (!WriteProcessMemory(hProcess, address, buffer, size, &dwWriteByteCount))
		dwWriteByteCount = 0;
	return (dwWriteByteCount != 0);
}

bool Memory::writeAdressSafe(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size)
{
	SIZE_T dwWriteByteCount = 0;
	__try {
		if (!WriteProcessMemory(hProcess, address, buffer, size, &dwWriteByteCount))
			dwWriteByteCount = 0;
	}
	__except (1) { }
	return (dwWriteByteCount && dwWriteByteCount == size);
}

bool Memory::protectMemory(HANDLE hProcess, LPVOID address, std::size_t size, DWORD dwProtectFlag)
{
	DWORD dwOldProtect = 0;
	return (VirtualProtectEx(hProcess, address, size, dwProtectFlag, &dwOldProtect) == TRUE);
}

bool Memory::patch(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size)
{
	DWORD dwOldProtect = 0;
	if (VirtualProtectEx(hProcess, address, size, PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
		return false;

	if (!writeAdressSafe(hProcess, address, buffer, size))
		return false;

	if (VirtualProtectEx(hProcess, address, size, dwOldProtect, &dwOldProtect) == FALSE)
		return false;

	return true;
}

bool Memory::isSafePage(HANDLE hProcess, LPVOID address)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
		return false;

	if (!(mbi.State & MEM_COMMIT))
		return false;

	if (mbi.State & MEM_RELEASE)
		return false;

	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect & PAGE_GUARD)
		return false;

	if (mbi.Protect != PAGE_READONLY && mbi.Protect != PAGE_READWRITE && mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE)
		return false;

	return true;
}

bool Memory::loadShellCode(HANDLE hProcess, LPVOID lpShellCode, std::size_t uiSize, LPVOID lpParam, std::size_t uiParamSize, DWORD dwTimeoutInterval)
{
	auto lpAddr = lpShellCode;
	if (uiSize != -1) //if size == (DWORD)-1 use already commited address
	{
		lpAddr = Commit(hProcess, lpShellCode, uiSize);
	}
	if (!lpAddr)
		return false;

	LPVOID lpCommitedParam = nullptr;
	if (lpParam)
	{
		lpCommitedParam = Commit(hProcess, lpParam, uiParamSize);
		if (!lpCommitedParam)
		{
			return false;
		}
	}

	return false;


}
