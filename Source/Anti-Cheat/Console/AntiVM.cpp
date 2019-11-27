#include "AntiVM.h"
#include <TlHelp32.h>



bool AntiVM::CheckLoadedDLLs()
{
	HMODULE hDll;

	const char* Dlls[] = {
		"sbiedll.dll",		// Sandboxie
		//"dbghelp.dll",		// WindBG
		"api_log.dll",		// iDefense Lab
		"dir_watch.dll",	//iDefense Lab
		"pstorec.dll",		// SunBelt Sandbox
		"vmcheck.dll",		// Virtual PC
		"wpespy.dll",		// WPE Pro
		"cmdvrt64.dll",		// Comodo Container
		"cmdvrt32.dll",
	};

	WORD wLenght = sizeof(Dlls) / sizeof(Dlls[0]);
	for (int i = 0; i < wLenght; ++i)
	{
		hDll = GetModuleHandleA(Dlls[i]);
		if (hDll)
		{
			printf_s("Found Dll: %s ", Dlls[i]);
			return true;
		}
	}
	return false;
}

bool AntiVM::CheckRegKeys()
{
	/* Array of strings of blacklisted registry keys */
	std::wstring szKeys[] = {
		(L"HARDWARE\\ACPI\\DSDT\\VBOX__"),
		(L"HARDWARE\\ACPI\\FADT\\VBOX__"),
		(L"HARDWARE\\ACPI\\RSDT\\VBOX__"),
		(L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
		(L"SOFTWARE\\Oracle\\VirtualBox\\Version"),
		(L"SYSTEM\\ControlSet001\\Services\\VBoxGuest"),
		(L"SYSTEM\\ControlSet001\\Services\\VBoxMouse"),
		(L"SYSTEM\\ControlSet001\\Services\\VBoxService"),
		(L"SYSTEM\\ControlSet001\\Services\\VBoxSF"),
		(L"SYSTEM\\ControlSet001\\Services\\VBoxVideo"),
		(L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"),
		(L"SOFTWARE\\Wine")
	};

	WORD wLenght = sizeof(szKeys) / sizeof(szKeys[0]);

	for (int i = 0; i < wLenght; ++i)
	{
		std::wstring RegistryPath = szKeys[i];
		HKEY Key;
		LONG Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegistryPath.c_str(), 0, KEY_ALL_ACCESS, &Key);
		RegCloseKey(Key);

		if (Result == ERROR_SUCCESS)
		{
			return true;
		}
	}

	return false;
}

bool AntiVM::CheckDevices()
{
	const char* devices[] = {
		"\\\\.\\VBoxMiniRdrDN",
		"\\\\.\\VBoxGuest",
		"\\\\.\\pipe\\VBoxMiniRdDN",
		"\\\\.\\VBoxTrayIPC",
		"\\\\.\\pipe\\VBoxTrayIPC"
	};

	WORD wLenght = sizeof(devices) / sizeof(devices[0]);

	for (int i = 0; i < wLenght; ++i)
	{
		HANDLE hFile = CreateFileA(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
			return true;
		}
	}

	return false;

}

bool AntiVM::CheckWindows()
{
	HWND hClass = FindWindowA("VBoxTrayToolWndClass", NULL);
	HWND hWindow = FindWindowA(NULL, "VBoxTrayToolWnd");

	if (hClass || hWindow)
		return true;

	return false;
}

bool AntiVM::CheckProcesses()
{
	
	static std::vector<std::wstring> processes;
	processes.push_back(L"VBoxService.exe");
	processes.push_back(L"VBoxTray.exe");
	processes.push_back(L"VMSrvc.exe");
	processes.push_back(L"VMUSrvc.exe");
	processes.push_back(L"xenservice.exe");
	processes.push_back(L"VirtualBox.exe");

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			std::wstring binaryPath = entry.szExeFile;
			for (auto name : processes)
			{
				if (binaryPath.find(name) != std::string::npos)
				{
					return true;
				}
			}

		}
	}
	processes.clear();
	CloseHandle(snapshot);
	return false;


}

