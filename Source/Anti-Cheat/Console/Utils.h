#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>

#define MAX_CLASSNAME 255
#define MAX_WNDNAME MAX_CLASSNAME

struct OverlayFinderParams {
	DWORD pidOwner = NULL;
	std::wstring wndClassName = L"";
	std::wstring wndName = L"";
	RECT pos = { 0, 0, 0, 0 }; // GetSystemMetrics with SM_CXSCREEN and SM_CYSCREEN can be useful here
	POINT res = { 0, 0 };
	float percentAllScreens = 0.0f;
	float percentMainScreen = 0.0f;
	DWORD style = NULL;
	DWORD styleEx = NULL;
	bool satisfyAllCriteria = false;
	std::vector<HWND> hwnds;
};

class Utils
{
public:
	static DWORD getProcessIdFromWindow(HWND window);
	static DWORD getProcessIdByName(std::wstring t_name);
	static DWORD getBaseAdressWithCRT(HANDLE process);
	static DWORD getModuleBaseAdress(DWORD procId, const wchar_t* modName);
	static bool IsProcessAlive(DWORD dwProcessID);
	static std::wstring getProcessNameFromProcessId(DWORD dwProcessId);
	static DWORD getProcessParentProcessId(DWORD dwMainProcessId);
	static std::vector<DWORD> getProcessIdsFromProcessName(std::wstring processName);
	static std::vector<DWORD> getProcessThreadIds(DWORD processID);
	static DWORD getFirstThreadFromProcessHandle(HANDLE hProc);
	static bool processHasThread(DWORD dwProcessID);
	static bool isFileExist(const std::wstring& name);
	static std::wstring getRandomString(int iLength);
	static bool isRunAsAdmin();
	static bool Injection(PCWSTR pszLibFile, DWORD dwProcessId);
	static void InjectDLL(const char* dllName, DWORD dwProcessId);
	static bool isSuspendedThread(DWORD dwThreadId);

	// https://www.unknowncheats.me/forum/anti-cheat-bypass/263403-window-hijacking-dont-overlay-betray.html
	static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam);
	static std::vector<HWND> OverlayFinder(OverlayFinderParams params);
};

