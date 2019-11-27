#include "ErrorHandler.h"


DWORD WINAPI CleanUpThread() {

	//Unload Driver
	//Terminate Game
	//Terminate Anti Cheat
	return 0;
}

void ErrorHandler::errorMessage(std::string ErrorCode, int ErrorType)
{
	std::string ErrorMessage = "Anti-Cheat Error\n Error Code: " + ErrorCode;
	std::string ErrorTypeStr;
	switch (ErrorType)
	{
	case 1:
		ErrorTypeStr = "Start Up Failure";
		break;
	case 2:
		ErrorTypeStr = "Cheat / Hack Detected";
		break;
	case 3:
		ErrorTypeStr = "Unknown Error";
		break;
	case 4:
		ErrorTypeStr = "Blacklisted Files Found";
		break;
	case 5:
		ErrorTypeStr = "Unusual Activies";
		break;
	case 6:
		ErrorTypeStr = "Debugger Found / VM Found";
		break;
	}

	MessageBoxA(0, (LPCSTR)ErrorMessage.c_str(), (LPCSTR)ErrorTypeStr.c_str(), MB_OK);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CleanUpThread, NULL, NULL, NULL);
	Sleep(400);
	exit(1);
}

void ErrorHandler::errorMessageW(std::wstring ErrorCode, int ErrorType)
{
	std::wstring ErrorMessage = L"Anti-Cheat Error\n Error Code: " + ErrorCode;
	std::wstring ErrorTypeStr;
	switch (ErrorType)
	{
	case 1:
		ErrorTypeStr = L"Start Up Failure";
		break;
	case 2:
		ErrorTypeStr = L"Cheat / Hack Detected";
		break;
	case 3:
		ErrorTypeStr = L"Unknown Error";
		break;
	case 4:
		ErrorTypeStr = L"Blacklisted Files Found";
		break;
	case 5:
		ErrorTypeStr = L"Unusual Activies";
		break;
	case 6:
		ErrorTypeStr = L"Debugger Found / VM Found";
		break;
	}

	MessageBoxW(0, (LPWSTR)ErrorMessage.c_str(), (LPWSTR)ErrorTypeStr.c_str(), MB_OK);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CleanUpThread, NULL, NULL, NULL);
	Sleep(400);
	exit(1);
}
