
#include <iostream>
#include "DynamicWinAPI.h"
#include "Utils.h"
#include "AntiDebug.h"
#include "ErrorHandler.h"
#include "AntiVM.h"
#include "DriverIO.h"
#include "DriverIORequests.h"
#include "Service.h"

//#define THIRD_PARTY

enum eErrorCode {
	StartUpFailure = 1,
	CheatDetected = 2,
	UnknownError = 3,
	BlacklistedFilesFound = 4,
	UnusualActivities = 5,
	DebuggerVMFound = 6,
};


using namespace std;
HANDLE hProcGame = NULL;
HANDLE hThreadGame = NULL;
HANDLE hThreadMain = NULL;
HANDLE hDriver = NULL;
int GameProcessID = 0;
DWORD TidMain = 0;

const char* GameWindowName = "HackMe"; //Needed for overlay detector
const wchar_t* GameProcessName = L"HackMe.exe"; //for everything else

HANDLE hAntiDebugThread = NULL;
DWORD TidAntiDebug = 0;
DWORD WINAPI AntiDebugThread()
{
	AntiDebug::hideThread(GetCurrentThread());
	while (true)
	{
		if (AntiDebug::isDebuggerPresentAPI())
		{			
			ErrorHandler::errorMessage("DB1 Debugger Present API", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::checkRemoteDebuggerPresentAPI())
		{
			ErrorHandler::errorMessage("DB2 Remote Debugger Present", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::hasHardwareBreakpoints())
		{
			ErrorHandler::errorMessage("DB3 Hardware Breakpoints detected", eErrorCode::DebuggerVMFound);
		}		
		Sleep(200);
		if (AntiDebug::canCallOutputDebugString())
		{
			ErrorHandler::errorMessage("Can call output debug string", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::debuggerDriversPresent())
		{
			ErrorHandler::errorMessage("DB5 Debug Drivers Found", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::has03BreakpointHandler())
		{
			ErrorHandler::errorMessage("DB6 0x03 Breakpoint detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::has2DBreakpointHandler())
		{
			ErrorHandler::errorMessage("DB7 0x2D Breakpoint detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiDebug::hasRIPExceptionHandler())
		{
			ErrorHandler::errorMessage("DB8 RIP ExceptionHandler found", eErrorCode::DebuggerVMFound);
		}
		Sleep(1000);
		


	}
}

HANDLE hAntiVMThread = NULL;
DWORD TidAntiVM = 0;
DWORD WINAPI AntiVMThread() 
{
	AntiDebug::hideThread(GetCurrentThread());
	while (true)
	{
		if (AntiVM::CheckLoadedDLLs())
		{
			ErrorHandler::errorMessage("VM DLLs detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiVM::CheckRegKeys())
		{
			ErrorHandler::errorMessage("VM RegKeys detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiVM::CheckDevices())
		{
			ErrorHandler::errorMessage("VM Devices detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiVM::CheckWindows())
		{
			ErrorHandler::errorMessage("VM Window detected", eErrorCode::DebuggerVMFound);
		}
		Sleep(200);
		if (AntiVM::CheckProcesses())
		{
			ErrorHandler::errorMessage("VM Process detected", eErrorCode::DebuggerVMFound);
		}

		Sleep(5555);
	}
}

HANDLE hGameCheckerThread = NULL;
DWORD TidGameChecker = 0;
DWORD WINAPI GameValidCheckThread()
{
	AntiDebug::hideThread(GetCurrentThread());
	while (1)
	{
		if(GameProcessID != 0)
		{
			if (!Utils::IsProcessAlive(GameProcessID))
			{
				ErrorHandler::errorMessage("Game Stopped Running", eErrorCode::UnknownError);
			}
		}
		Sleep(1000);
	}
}

HANDLE hCommonCheatsScannerThread = NULL;
DWORD TidCommonCheatsScanner = 0;
DWORD WINAPI CommonCheatsDriverScannerThread()
{
	AntiDebug::hideThread(GetCurrentThread());
	while (1)
	{
		const char CheatingDrivers[5][20] = {
			"\\\\.\\kernelhop", "\\\\.\\BlackBone",
			"\\\\.\\VBoxDrv", "\\\\.\\Htsysm72FB",
			"\0"
		};

		for (int i = 0; CheatingDrivers[i][0] != '\0'; i++)
		{
			HANDLE hCheats = CreateFileA(CheatingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
			if (hCheats != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hCheats);
				ErrorHandler::errorMessage("Cheating Drivers Found", eErrorCode::CheatDetected);
			}
			CloseHandle(hCheats);
			Sleep(200);
		}
		Sleep(2000);
	}
}

HANDLE hOverlayScannerThread = NULL;
DWORD TidOverlayScanner = 0;
DWORD WINAPI OverlayScannerThread()
{
	// https://www.unknowncheats.me/forum/anti-cheat-bypass/263403-window-hijacking-dont-overlay-betray.html
	AntiDebug::hideThread(GetCurrentThread());

	Sleep(1000);
	//Find the window of the game
	HWND gameWindow = FindWindowA(NULL, GameWindowName);
	if (gameWindow == NULL)
		ErrorHandler::errorMessage("Please enter correct name of the game window in ac console source", 1);
	
	OverlayFinderParams params;
	params.style = WS_VISIBLE;
	params.styleEx = WS_EX_LAYERED | WS_EX_TRANSPARENT;
	params.satisfyAllCriteria = true;


	while (1)
	{
		//Get position of the game
		RECT pos;
		GetWindowRect(gameWindow, &pos);
		if (pos.left || pos.top || pos.right || pos.bottom)
			params.pos = pos;

		//Get size of the game
		POINT res;
		res.x = pos.right - pos.left;
		res.y = pos.bottom - pos.top;
		params.res = res;
	

		//Get all windows that match the params
		vector<HWND> hwnds = Utils::OverlayFinder(params);
		
		//static wstring OutputString = L"Found Windows: \n";
		//static bool shown = false;
		for (int i = 0; i < hwnds.size(); ++i)
		{
			DWORD ProcessIDForOverlay = 0;
			DWORD tid = GetWindowThreadProcessId(hwnds[i], &ProcessIDForOverlay);
			if (Utils::IsProcessAlive(ProcessIDForOverlay))
			{

				
				//OutputString.append(Utils::getProcessNameFromProcessId(ProcessIDForOverlay).c_str());
				//OutputString.append(L"\n");
				//wprintf_s(L"%s \n", Utils::getProcessNameFromProcessId(ProcessIDForOverlay).c_str());
				if (Utils::getProcessNameFromProcessId(ProcessIDForOverlay) != L"Console.exe")
					ErrorHandler::errorMessage("Overlay Found!", eErrorCode::CheatDetected);
					//TerminateProcess(OpenProcess(THREAD_TERMINATE, false, ProcessIDForOverlay), NULL);
			}
			Sleep(100);
		}

		//if (!shown)
		//
		//	MessageBoxW(0, OutputString.c_str(), L"Overlays Detected", MB_OK);
		//	shown = true;
		//}
		
		//OutputString.clear();
		//OutputString = L"Found Windows: \n";
		Sleep(6666);
	}
}

HANDLE hAntiKillThread = NULL;
DWORD TidAntiKill = 0;
DWORD WINAPI AntiKillThread()
{
	AntiDebug::hideThread(GetCurrentThread());
	while (1)
	{
		if(Utils::isSuspendedThread(TidAntiDebug) || Utils::isSuspendedThread(TidGameChecker)
			|| Utils::isSuspendedThread(TidCommonCheatsScanner) || Utils::isSuspendedThread(TidOverlayScanner) 
			|| Utils::isSuspendedThread(TidMain) || Utils::isSuspendedThread(TidAntiVM))
		{
			ErrorHandler::errorMessage("AK1 Thread Mismatched", eErrorCode::DebuggerVMFound);
		}

		Sleep(1000);

	}
}


int main()
{
	if (!Utils::isRunAsAdmin())
	{
		printf_s("Please run as Admin");
		getchar();
		return 0;
	}
		


	printf_s("------------Anti-Cheat Started----------- \n");

	//Dynamic API -> Unnötig
	shared_ptr<DynamicWinapi> winAPIHelper = make_shared<DynamicWinapi>();
	winAPIHelper->Initialize();

	TidMain = GetCurrentThreadId();

	//Load Driver:
	////////////////////////////////////////////////////
	const char* DriverName = "AntiCheatDriver";
	const char* DisplayName = "AntiCheatDriver";
	const char* DriverLocation = "Driver.sys"; 
	CService service(DriverLocation, DriverName, DisplayName, SERVICE_DEMAND_START);
	ErrorHandler::setService(&service);

	//Test if driver is already loaded. if -> unload
	HANDLE hCheckDriver = CreateFileA("\\\\.\\AntiCheatDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hCheckDriver != INVALID_HANDLE_VALUE)
	{
		ErrorHandler::unloadDriver(DriverName);
		CloseHandle(hCheckDriver);
	}
	
	//Load Driver
	bool loaded = ErrorHandler::loadDriver();
	Sleep(100);
	hDriver = CreateFileA("\\\\.\\AntiCheatDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	printf_s("hDriver handle = %i \n", (int)hDriver);
	printf_s("Driver loaded: %i \n", (int)loaded);
	////////////////////////////////////////////////////////



	//Starting Threads:
	hAntiDebugThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiDebugThread, NULL, 0, &TidAntiDebug);
	if (hAntiDebugThread != INVALID_HANDLE_VALUE)
		printf_s("Started Anti-Debug Thread \n");

	hAntiVMThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiVMThread, NULL, 0, &TidAntiVM);
	if (hAntiVMThread != INVALID_HANDLE_VALUE)
		printf_s("Started Anti-VM Thread \n");
	
	hCommonCheatsScannerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CommonCheatsDriverScannerThread, NULL, 0, &TidCommonCheatsScanner);
	if (hCommonCheatsScannerThread != INVALID_HANDLE_VALUE)
		printf_s("Started Common Driver Scanner Thread \n");

	
#ifndef THIRD_PARTY




	//Start Process/Game to protect
	STARTUPINFOA info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;
	CreateProcessA("HackMe.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &info, &processInfo);
	hProcGame = processInfo.hProcess;
	hThreadGame = processInfo.hThread;
	GameProcessID = processInfo.dwProcessId;
	printf_s("\n ------------Started Game------------ \n");

#endif // !THIRD_PARTY

#ifdef THIRD_PARTY
	Sleep(2000);

	//Wenn ein 3rd-Party Spiel geschützt werden soll, das define am anfang dieser Datei einkommentieren und den ensprechenden Process und Fensternamen eintragen.
	GameProcessID = Utils::getProcessIdByName(GameProcessName);
#endif // THIRD_PARTY

	

	if (GameProcessID == -1)
		printf_s("Can't find target process");

	hGameCheckerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GameValidCheckThread, NULL, 0, &TidGameChecker);
	if (hGameCheckerThread != INVALID_HANDLE_VALUE)
		printf_s("\nStarted Game Valid Checker \n");

	hOverlayScannerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OverlayScannerThread, NULL, 0, &TidOverlayScanner);
	if (hOverlayScannerThread != INVALID_HANDLE_VALUE)
		printf_s("Started Overlay Scanner Thread \n");
	
	//hAntiKillThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiKillThread, NULL, 0, &TidAntiKill);
	if (hAntiKillThread != INVALID_HANDLE_VALUE)
		printf_s("Started Anti Thread Kill \n");

	//Find path to the AC-DLL. AC.exe and DLL must be in the folder
	Sleep(200);
	char buff[255];
	GetModuleFileNameA(GetModuleHandleA(NULL), buff, 255);
	std::string path(buff);
	path.append("\\..\\DLL.dll");

	//Inject Anti-Cheat DLL
	Utils::InjectDLL(path.c_str(), GameProcessID);

	
	//Wenn Treiber vorhanden ist, übermittle die IDs der nicht zu beschränkenden Prozesse
	if (hDriver != INVALID_HANDLE_VALUE )
	{
		//Find Whitelisted Process Ids
		std::vector<DWORD> CsrssIds = Utils::getProcessIdsFromProcessName(L"csrss.exe");
		if (CsrssIds.size() < 2)
			printf_s("Error finding Csrss Process \n");

		std::vector<DWORD> LsassIds = Utils::getProcessIdsFromProcessName(L"lsass.exe");
		if (LsassIds.empty())
			printf_s("Error finding Lsass Process \n");
	
		//Send Process Ids to protect
		KERNEL_PROCESS_INFO processesInfo;
		processesInfo.pidGame = (ULONG)GameProcessID;
		processesInfo.pidUserModeAntiCheat = (ULONG)GetProcessId(NULL);
		processesInfo.bReceived = 0;
		if (!DriverIORequests::SendProcesses(hDriver, &processesInfo))
			printf_s("\n Something went wrong sending the process ids \n");
			
		//Send Whitelisted Process Ids
		KERNEL_SYSTEMPROCESS_INFO sysProcessesInfo;
		sysProcessesInfo.pidCsrss1 = (ULONG)CsrssIds[0];
		sysProcessesInfo.pidCsrss2 = (ULONG)CsrssIds[1];
		sysProcessesInfo.pidLsass = (ULONG)LsassIds[0];
		if (!DriverIORequests::SendSystemProcesses(hDriver, &sysProcessesInfo))
			printf_s("\n Something went wrong sending the Sys process ids \n");
		
	}

	//Keep process alive
	while (1)
	{
		Sleep(4000);
	}
	


	
	
}
