#pragma once
#include <Windows.h>
#include <iostream>


class Memory
{
public:
	

	static LPVOID Alloc(HANDLE hProcess, std::size_t size, DWORD dwProtection = PAGE_EXECUTE_READWRITE, LPVOID pPreferredLoc = nullptr);
	static LPVOID Commit(HANDLE hProcess, LPVOID data, std::size_t size);
	static bool Free(HANDLE hProcess, LPVOID address, std::size_t size);

	static bool readAdress(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size);
	static bool readAdressSafe(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size);
	static bool writeAdress(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size);
	static bool writeAdressSafe(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size);

	

	template<typename T>
	static T RPM(HANDLE process, DWORD_PTR adress);

	template<typename T>
	static void WPM(HANDLE process, DWORD_PTR adress, T value);

	template<typename T>
	static T RPM_Safe(HANDLE hProcess, DWORD_PTR address);

	template<typename T>
	static void WPM_Safe(HANDLE hProcess, DWORD_PTR address, T value);


	template<typename T>
	static DWORD protectMemoryT(HANDLE process, DWORD_PTR adress, DWORD prot);

	static bool protectMemory(HANDLE hProcess, LPVOID address, std::size_t size, DWORD dwProtectFlag);

	template<int SIZE>
	static void writeNop(HANDLE hProcess, DWORD adress);

	static bool patch(HANDLE hProcess, LPVOID address, LPVOID buffer, std::size_t size);

	static bool isSafePage(HANDLE hProcess, LPVOID address);

	static bool loadShellCode(HANDLE hProcess, LPVOID lpShellCode, std::size_t uiSize, LPVOID lpParam, std::size_t uiParamSize, DWORD dwTimeoutInterval = INFINITE);


};

