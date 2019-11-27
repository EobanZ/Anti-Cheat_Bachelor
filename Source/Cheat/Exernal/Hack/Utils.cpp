#include "pch.h"
#include "Utils.h"
#include <TlHelp32.h>
#include <stdlib.h>
#include <algorithm>



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

HANDLE Utils::CreateThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpThreadRoutine, LPVOID lpParam, DWORD dwFlag)
{
	HANDLE hThread = INVALID_HANDLE_VALUE;

	return hThread;
	
}

std::wstring Utils::toLower(std::wstring szSource)
{
	std::wstring szLowerCopy(szSource.begin(), szSource.end());
	std::transform(szLowerCopy.begin(), szLowerCopy.end(), szLowerCopy.begin(), tolower);
	return szLowerCopy;
}

std::string Utils::getExeNameWithPath()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	return std::string(buffer);
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

DWORD Utils::getStringHash(LPVOID lpBuffer, BOOL bUnicode, UINT uLen)
{
	DWORD dwHash = 0;
	LPSTR strBuffer = (LPSTR)lpBuffer;

	while (uLen--)
	{
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += (DWORD)*strBuffer++;

		if (bUnicode)
			strBuffer++;
	}
	return dwHash;
}

bool Utils::isFileExist(const std::wstring & name)
{
	DWORD dwAttrib = GetFileAttributesW(name.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

ULONG Utils::getRandomInt(ULONG uMin, ULONG uMax)
{
	if (uMax < (ULONG)0xFFFFFFFF)
		uMax++;

	return (rand() % (uMax - uMin)) + uMin;
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

bool Utils::isProcessElevated()
{
	BOOL fIsElevated = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}

	if (ERROR_SUCCESS != dwError)
		throw dwError;

	return fIsElevated;
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



