#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
class Utils
{
public:
	static DWORD getProcessIdFromWindow(HWND window);
	static DWORD getProcessIdByName(std::wstring t_name);
	static DWORD getBaseAdressWithCRT(HANDLE process); 
	static DWORD getModuleBaseAdress(DWORD procId, const wchar_t* modName); 
	static HANDLE CreateThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpThreadRoutine, LPVOID lpParam, DWORD dwFlag = 0);
	static std::wstring toLower(std::wstring szSource);
	static std::string getExeNameWithPath();
	static bool IsProcessAlive(DWORD dwProcessID);
	static std::wstring getProcessNameFromProcessId(DWORD dwProcessId);
	static DWORD getProcessParentProcessId(DWORD dwMainProcessId);
	static std::vector<DWORD> getProcessIdsFromProcessName(std::wstring processName);
	static std::vector<DWORD> getProcessThreadIds(DWORD processID);
	static DWORD getFirstThreadFromProcessHandle(HANDLE hProc);
	static bool processHasThread(DWORD dwProcessID);
	static DWORD getStringHash(LPVOID lpBuffer, BOOL bUnicode, UINT uLen);
	static bool isFileExist(const std::wstring& name);
	static ULONG getRandomInt(ULONG uMin, ULONG uMax);
	static std::wstring getRandomString(int iLength);
	static bool isRunAsAdmin();
	static bool isProcessElevated();
};

