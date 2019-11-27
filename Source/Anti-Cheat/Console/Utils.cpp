#include "Utils.h"
#include <TlHelp32.h>
#include <stdlib.h>
#include <algorithm>
#include "ThreadEnumerator.h"




DWORD Utils::getProcessIdFromWindow(HWND window)
{
	DWORD PID;
	GetWindowThreadProcessId(window, &PID);
	return PID;
}

DWORD Utils::getProcessIdByName(std::wstring t_name)
{
	DWORD PID = -1;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			std::wstring binaryPath = entry.szExeFile;
			if (binaryPath.find(t_name) != std::wstring::npos)
			{
				PID = entry.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(snapshot);
	return PID;
}

DWORD Utils::getBaseAdressWithCRT(HANDLE process)
{
	DWORD newBase;
	// get the adress of kernel32.dll
	HMODULE k32 = GetModuleHandleA("kernel32.dll");

	// get the adress of GetModuleHandle()
	LPVOID funcAdr = GetProcAddress(k32, "GetModuleHandleA");
	if (!funcAdr) funcAdr = GetProcAddress(k32, "GetModuleHandleW");

	//create thread in remote process
	HANDLE thread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)funcAdr, NULL, NULL, NULL);

	// let the thread finish
	WaitForSingleObject(thread, INFINITE);

	// get the exit code
	GetExitCodeThread(thread, &newBase);

	return newBase;
}

DWORD Utils::getModuleBaseAdress(DWORD procId, const wchar_t * modName)
{
	DWORD modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (DWORD)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}



bool Utils::IsProcessAlive(DWORD dwProcessID)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return false;

	PROCESSENTRY32 pt;
	pt.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pt)) {
		do {
			if (pt.th32ProcessID == dwProcessID) {
				CloseHandle(hSnapshot);
				return true;
			}
		} while (Process32Next(hSnapshot, &pt));
	}

	CloseHandle(hSnapshot);
	return false;
}

DWORD Utils::getProcessParentProcessId(DWORD dwMainProcessId)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	DWORD dwProcessId = 0;

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (pe.th32ProcessID == dwMainProcessId) {
				dwProcessId = pe.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return (dwProcessId);
}

std::vector<DWORD> Utils::getProcessIdsFromProcessName(std::wstring processName)
{
	std::vector <DWORD> vPIDs;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot || hSnapshot == INVALID_HANDLE_VALUE)
		return vPIDs;

	if (Process32First(hSnapshot, &entry) == TRUE)
	{
		while (Process32Next(hSnapshot, &entry) == TRUE)
		{
			std::wstring binaryPath = entry.szExeFile;
			if (binaryPath.find(processName) != std::wstring::npos)
			{
				vPIDs.emplace_back(entry.th32ProcessID);

			}
		}
	}

	CloseHandle(hSnapshot);
	return vPIDs;

}

std::vector<DWORD> Utils::getProcessThreadIds(DWORD processID)
{
	std::vector<DWORD> threads;

	HANDLE thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (thSnapshot == INVALID_HANDLE_VALUE)
		throw std::runtime_error("get_process_thread_id(): unable to create toolhelp snapshot");

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	BOOL retval = Thread32First(thSnapshot, &te);
	while (retval)
	{
		if (te.th32OwnerProcessID == processID)
			threads.push_back(te.th32ThreadID);

		retval = Thread32Next(thSnapshot, &te);
	}

	CloseHandle(thSnapshot);

	if (threads.empty())
		throw std::runtime_error("Failed getting process threads");

	return threads;
}

DWORD Utils::getFirstThreadFromProcessHandle(HANDLE hProc)
{
	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(snapshot, &entry) == TRUE) {
		DWORD PID = GetProcessId(hProc);
		while (Thread32Next(snapshot, &entry) == TRUE) {
			if (entry.th32OwnerProcessID == PID) {
				CloseHandle(snapshot);
				return entry.th32ThreadID;
			}
		}
	}
	CloseHandle(snapshot);
	return NULL;
}

bool Utils::processHasThread(DWORD dwProcessID)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnap == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (Thread32First(hSnap, &ti))
	{
		do {
			if (dwProcessID == ti.th32OwnerProcessID) {
				CloseHandle(hSnap);
				return true;
			}
		} while (Thread32Next(hSnap, &ti));
	}

	CloseHandle(hSnap);
	return false;
}


bool Utils::isFileExist(const std::wstring & name)
{
	DWORD dwAttrib = GetFileAttributesW(name.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


std::wstring Utils::getRandomString(int iLength)
{
	WCHAR __alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 0x0 }; // abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
	static std::wstring charset = __alphabet;
	std::wstring result;
	result.resize(iLength);

	for (int i = 0; i < iLength; i++)
		result[i] = charset[rand() % charset.length()];

	return result;
}

bool Utils::isRunAsAdmin()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	if (ERROR_SUCCESS != dwError)
		throw dwError;

	return fIsRunAsAdmin;
}


bool Utils::Injection(PCWSTR pszLibFile, DWORD dwProcessId)
{
	// Calculate the number of bytes needed for the DLL's pathname
	DWORD dwSize = (lstrlenW(pszLibFile) + 1) * sizeof(wchar_t);

	// Get process handle passing in the process ID
	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE, dwProcessId);
	if (hProcess == NULL)
		return false;


	// Allocate space in the remote process for the pathname
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
		return false;

	// Copy the DLL's pathname to the remote process address space
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, dwSize, NULL);
	if (n == 0)
		return false;

	// Get the real address of LoadLibraryW in Kernel32.dll
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
		return false;

	// Create a remote thread that calls LoadLibraryW(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL)
		return false;

	//Wait for the remote thread to terminate
	WaitForSingleObject(hThread, INFINITE);

	// Free the remote memory that contained the DLL's pathname and close Handles
	if (pszLibFileRemote != NULL)
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

	if (hThread != NULL)
		CloseHandle(hThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	return true;

	
}

void Utils::InjectDLL(const char * dllName, DWORD dwProcessId)
{
	auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProc == INVALID_HANDLE_VALUE)
		printf("Faild to create Handle to target process \n");


	int namelen = strlen(dllName) + 1;
	LPVOID remoteString = VirtualAllocEx(hProc, NULL, namelen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProc, remoteString, dllName, namelen, NULL);

	LPVOID loadLib = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

	HANDLE thread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLib, remoteString, NULL, NULL);

	WaitForSingleObject(thread, INFINITE);
	VirtualFreeEx(hProc, remoteString, namelen, MEM_RELEASE);
	CloseHandle(thread);
}

bool isSuspendedThread2(DWORD dwThreadId)
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

bool Utils::isSuspendedThread(DWORD dwThreadId)
{
	//diese Funktion ist stabiler
	return isSuspendedThread2(dwThreadId);

	auto threadEnumerator = new CThreadEnumerator(GetCurrentProcessId());
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



BOOL Utils::EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
	using namespace std;
	OverlayFinderParams& params = *(OverlayFinderParams*)lParam;

	unsigned char satisfiedCriteria = 0, unSatisfiedCriteria = 0;

	// If looking for windows of a specific PDI
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (params.pidOwner != NULL)
		if (params.pidOwner == pid)
			++satisfiedCriteria; // Doesn't belong to the process targeted
		else
			++unSatisfiedCriteria;

	// If looking for windows of a specific class
	wchar_t className[MAX_CLASSNAME] = L"";
	GetClassName(hwnd, (LPWSTR)className, MAX_CLASSNAME);
	wstring classNameWstr = className;
	if (params.wndClassName != L"")
		if (params.wndClassName == classNameWstr)
			++satisfiedCriteria; // Not the class targeted
		else
			++unSatisfiedCriteria;

	// If looking for windows with a specific name
	wchar_t windowName[MAX_WNDNAME] = L"";
	GetWindowText(hwnd, (LPWSTR)windowName, MAX_CLASSNAME);
	wstring windowNameWstr = windowName;
	if (params.wndName != L"")
		if (params.wndName == windowNameWstr)
			++satisfiedCriteria; // Not the class targeted
		else
			++unSatisfiedCriteria;

	// If looking for window at a specific position
	RECT pos;
	GetWindowRect(hwnd, &pos);
	if (params.pos.left || params.pos.top || params.pos.right || params.pos.bottom)
		if (params.pos.left == pos.left && params.pos.top == pos.top && params.pos.right == pos.right && params.pos.bottom == pos.bottom)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// If looking for window of a specific size
	POINT res = { pos.right - pos.left, pos.bottom - pos.top };
	if (params.res.x || params.res.y)
		if (res.x == params.res.x && res.y == params.res.y)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// If looking for windows taking more than a specific percentage of all the screens
	float ratioAllScreensX = res.x / GetSystemMetrics(SM_CXSCREEN);
	float ratioAllScreensY = res.y / GetSystemMetrics(SM_CYSCREEN);
	float percentAllScreens = ratioAllScreensX * ratioAllScreensY * 100;
	if (params.percentAllScreens != 0.0f)
		if (percentAllScreens >= params.percentAllScreens)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// If looking for windows taking more than a specific percentage or the main screen
	RECT desktopRect;
	GetWindowRect(GetDesktopWindow(), &desktopRect);
	POINT desktopRes = { desktopRect.right - desktopRect.left, desktopRect.bottom - desktopRect.top };
	float ratioMainScreenX = res.x / desktopRes.x;
	float ratioMainScreenY = res.y / desktopRes.y;
	float percentMainScreen = ratioMainScreenX * ratioMainScreenY * 100;
	if (params.percentMainScreen != 0.0f)
		if (percentAllScreens >= params.percentMainScreen)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// Looking for windows with specific styles
	LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
	if (params.style)
		if (params.style & style)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// Looking for windows with specific extended styles
	LONG_PTR styleEx = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
	if (params.styleEx)
		if (params.styleEx & styleEx)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	if (!satisfiedCriteria)
		return TRUE;

	if (params.satisfyAllCriteria && unSatisfiedCriteria)
		return TRUE;

	// If looking for multiple windows
	params.hwnds.push_back(hwnd);
	return TRUE;
}

std::vector<HWND> Utils::OverlayFinder(OverlayFinderParams params)
{
	EnumWindows(EnumWindowsCallback, (LPARAM)&params);
	return params.hwnds;
}

std::wstring Utils::getProcessNameFromProcessId(DWORD dwProcessId)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return std::wstring(L"");

	std::wstring szResult;

	PROCESSENTRY32 pt;
	pt.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pt)) {
		do {
			if (dwProcessId == pt.th32ProcessID) {
				szResult = pt.szExeFile;
				CloseHandle(hSnapshot);
				return szResult;
			}
		} while (Process32Next(hSnapshot, &pt));
	}

	CloseHandle(hSnapshot);
	return szResult;
}



