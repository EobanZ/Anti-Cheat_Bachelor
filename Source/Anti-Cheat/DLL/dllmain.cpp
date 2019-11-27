// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.
#include "stdafx.h"
#include <iostream>
#include "AntiDebug.h"
#include "ErrorHandler.h"
#include "Utils.h"
#include "DLLCheck.h"
#include "ThreadCheck.h"
#include "XOR.h"
#include "MemoryEnumeration.h"
#include "AntiHooks.h"
using namespace std;

enum eErrorCode {
	StartUpFailure = 1,
	CheatDetected = 2,
	UnknownError = 3,
	BlacklistedFilesFound = 4,
	UnusualActivities = 5,
	DebuggerVMFound = 6,
};

typedef struct _signature{
	_signature(const char* pattern, const char* mask) {
		this->pattern = pattern;
		this->mask = mask;
	}
	const char* pattern;
	const char* mask;
}signature;

DWORD TidMain = 0;

HANDLE hAntiDebugThread = INVALID_HANDLE_VALUE;
DWORD TidAntiDebug = 0;
DWORD WINAPI AntiDebugThread()
{
	AntiDebug::hideThread(GetCurrentThread());
	while (true)
	{
		if (AntiDebug::isDebuggerPresentAPI())
		{
			ErrorHandler::errorMessage("DBINT1 Debugger Present API", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::checkRemoteDebuggerPresentAPI())
		{
			ErrorHandler::errorMessage("DBINT2 Remote Debugger Present", eErrorCode::DebuggerVMFound);;
		}
		Sleep(200);
		if (AntiDebug::hasHardwareBreakpoints())
		{
			ErrorHandler::errorMessage("DBINT3 Hardware Breakpoints detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::canCallOutputDebugString())
		{
			ErrorHandler::errorMessage("Can call output debug string", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::debuggerDriversPresent())
		{
			ErrorHandler::errorMessage("DBINT5 Debug Drivers Found", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::has03BreakpointHandler())
		{
			ErrorHandler::errorMessage("DBINT6 0x03 Breakpoint detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::has2DBreakpointHandler())
		{
			ErrorHandler::errorMessage("DBINT7 0x2D Breakpoint detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::hasRIPExceptionHandler())
		{
			ErrorHandler::errorMessage("DBINT8 RIP ExceptionHandler found", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
	}
}

HANDLE hAntiHooksThread = INVALID_HANDLE_VALUE;
DWORD TidAntiHooks = 0;
DWORD WINAPI AntiHooksThread() {
	AntiDebug::hideThread(GetCurrentThread());
	while (true)
	{
		
		if (AntiHooks::IAT_HookCheck2())
		{
			ErrorHandler::errorMessage("IAT Hook detected", eErrorCode::CheatDetected);
		}
		Sleep(6000);
		
	}
}

HANDLE hMemoryEnumerationThread = INVALID_HANDLE_VALUE;
DWORD TidMemoryEnumeration = 0;
DWORD WINAPI MemoryEnumerationThread() 
{
	AntiDebug::hideThread(GetCurrentThread());

	SYSTEM_INFO sysinfo = { 0 };
	GetSystemInfo(&sysinfo);

	std::vector<std::wstring> blacklistedProcNames;
	blacklistedProcNames.push_back(L"Cheat Engine");
	blacklistedProcNames.push_back(L"cheatengine-x86_64");
	//blacklistedProcNames.push_back(L"Extreme Injector");
	blacklistedProcNames.push_back(L"x32dbg");
	blacklistedProcNames.push_back(L"x64dbg");

	std::vector<std::string> blacklistedWindowNames;
	blacklistedWindowNames.push_back("External Cheat");
	blacklistedWindowNames.push_back("Cheat Engine");

	std::vector<std::string> blacklistedImages;
	blacklistedImages.push_back("nvToolsExt64_1.dll");
	blacklistedImages.push_back("ws2detour_x96.dll");
	blacklistedImages.push_back("networkdllx64.dll");
	blacklistedImages.push_back("nxdetours_64.dll");
	blacklistedImages.push_back("nvcompiler.dll");
	blacklistedImages.push_back("wmp.dll");
	blacklistedImages.push_back("VFTHook.dll");
	blacklistedImages.push_back("JumpHook.dll");
	blacklistedImages.push_back("IATHook.dll");
	blacklistedImages.push_back("CallHook.dll");

	std::vector<signature*> blacklistedSignatures; //TODO: neue Signature vom ferigen cheat finden
	blacklistedSignatures.push_back(&signature("\x9C\x60\xB8\x00\x00\x00\x00\xFF\xD0\x61\x9D\x89\x4A\x08\x8B\x55\xF8\xFF\x25", "xxx????xxxxxxxxxxxx"));
	blacklistedSignatures.push_back(&signature("\x68\x00\x00\x00\x00\x8B\x4C\x18\x38\xFF\x15\x00\x00\x00\x00\x83\xF8\x1D\x75\x2C\x85\xD2\x75\x28\x85\xFF\x7C\x33\x7F\x04\x85\xF6\x74\x2D\x8B\x03\x8B\x48\x04\x8A\x44\x19\x40\x8B\x4C\x19\x38\x88\x45\xE0\xFF\x75\xE0\xFF\x15\x00\x00\x00\x00\x83\xF8\xFF\x75\x07\xB9\x00\x00\x00\x00\xEB\x0A", "x????xxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxx????xx"));
	
	std::vector<std::string> blacklistedIpAddresses;
	blacklistedIpAddresses.push_back("193.174.220.108"); //Hs Kempten website
	blacklistedIpAddresses.push_back("104.25.155.26"); //www.unknowncheats.me
	blacklistedIpAddresses.push_back("104.25.10.103"); //perfectaim.io
	

	while (true)
	{
	
		
		
		//Patternscan for each blacklisted signature
		for (auto pat : blacklistedSignatures)
		{

			DWORD foundAddress = (DWORD)MemoryEnumeration::PatternScan((char*)sysinfo.lpMinimumApplicationAddress, (uintptr_t)sysinfo.lpMaximumApplicationAddress - (uintptr_t)sysinfo.lpMinimumApplicationAddress, pat->pattern, pat->mask, lstrlenA(pat->mask));

			if (foundAddress != 0)
				ErrorHandler::errorMessage("Cheat Signature Found", eErrorCode::CheatDetected);
			Sleep(100);
		}
		
		Sleep(1000);
		MemoryEnumeration::EnumerateWindows(&blacklistedWindowNames);

		Sleep(1000);
		MemoryEnumeration::EnumerateProcesses(&blacklistedProcNames);

		Sleep(1000);
		MemoryEnumeration::EnumerateImages(&blacklistedImages);

		Sleep(1000);
		MemoryEnumeration::EnumerateTcpTable(&blacklistedIpAddresses);

		Sleep(6000);
	}

	return 0;
}

HANDLE hMD5CheckThread = INVALID_HANDLE_VALUE;
DWORD TidMD5Check = 0;
DWORD WINAPI MD5CheckThread() {
	//Checks if the .text section of the module was edited after startup
	AntiDebug::hideThread(GetCurrentThread());

	std::string currMD5;
	std::string startupMD5;

	if (!Utils::GetModuleMD5(startupMD5))
		ErrorHandler::errorMessage(startupMD5, 1);


	while (true)
	{
		if(!Utils::GetModuleMD5(currMD5))
			ErrorHandler::errorMessage(currMD5, 1);
		
		if (startupMD5 != currMD5 )
			ErrorHandler::errorMessage("Module was edited", eErrorCode::CheatDetected);

		Sleep(5000);
	}
}

HANDLE hAntiKillThread = INVALID_HANDLE_VALUE;
DWORD TidAntiKill = 0;
DWORD WINAPI AntiKillThread() {
	AntiDebug::hideThread(GetCurrentThread());
	while (1)
	{
		if (Utils::isSuspendedThread2(TidAntiDebug) || Utils::isSuspendedThread2(TidMain) || Utils::isSuspendedThread2(TidAntiHooks) || Utils::isSuspendedThread2(TidMD5Check) || Utils::isSuspendedThread2(TidMemoryEnumeration))
		{
			ErrorHandler::errorMessage("AK1INT Thread Mismatched", eErrorCode::DebuggerVMFound);
		}
		Sleep(1000);
	}
}


HANDLE hMainThread = INVALID_HANDLE_VALUE;
DWORD WINAPI MainThread() {
	
	printf_s("\n-----------Anti-Cheat DLL injected into game process----------- \n");
	Sleep(1000);
	hAntiDebugThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiDebugThread, NULL, 0, &TidAntiDebug);
	if (hAntiDebugThread != INVALID_HANDLE_VALUE)
		printf_s("Started Internal Anti-Debug Thread \n");

	hAntiHooksThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiHooksThread, NULL, 0, &TidAntiHooks);
	if (hAntiHooksThread != INVALID_HANDLE_VALUE)
		printf_s("Started Internal Anti-Hooks Thread \n");

	hMemoryEnumerationThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemoryEnumerationThread, NULL, 0, &TidMemoryEnumeration);
	if (hMemoryEnumerationThread != INVALID_HANDLE_VALUE)
		printf_s("Started Internal MemoryEnumeration Thread \n");

	hMD5CheckThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MD5CheckThread, NULL, 0, &TidMD5Check);
	if (hMD5CheckThread != INVALID_HANDLE_VALUE)
		printf_s("Started Internal MD5-Check Thread \n");

	//hAntiKillThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiKillThread, NULL, 0, NULL); //Random abstuerze
	if (hAntiKillThread != INVALID_HANDLE_VALUE)
		printf_s("Started Internal Anti-Kill Thread \n");

	//Placing DllInjectionDetector Hooks.
	DLLCheck::InitializeDLLCheck();
	printf_s("Internal DLL Check Inizialized \n");
	ThreadCheck::InitializeThreadCheck();
	printf_s("Internal Thread Check Inizialized \n");
	

	//Keep Thread Alive
	while (1)
	{ 
		Sleep(2000);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	hMainThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, NULL, 0, &TidMain);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

