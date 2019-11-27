#include "ErrorHandler.h"


CService* service = nullptr; //Als member gabs immer nen Linker fehler den ich nicht beheben konnte. Deshalb jetzt dieser workaround

DWORD WINAPI CleanUpThread() {
	ErrorHandler::unloadDriver();
	//Terminate Game
	//Terminate Anti Cheat
	return 0;
}



void ErrorHandler::setService(CService * pService)
{
	service = pService;
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

bool ErrorHandler::unloadDriver()
{
	return service->StopSvc() == SVC_OK ? true : false;
	
}

bool ErrorHandler::unloadDriver(const char* DriverName)
{
	printf_s("Unloaded Driver \n");
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager == NULL)
		return false;
	 
	SC_HANDLE hService = OpenServiceA(hSCManager, DriverName, SERVICE_ALL_ACCESS);

	if (hService == NULL)
	{
		CloseServiceHandle(hSCManager);
		return true;
	}
	DeleteService(hService);
	CloseServiceHandle(hSCManager);

	return true;
}

bool ErrorHandler::loadDriver()
{
	if (!service)
		return false;

	//Create Service
	if (service->CreateSvc() == SVC_OK)
	{
		printf("Service creation: OK.\n");
	}	
	else {
		printf("Service creation: FAILD.\n");
		return false;
	}

	int errorCOde = 0;
	//Start Service
	if ((errorCOde = (int) service->StartSvc()) == SVC_OK)
	{
		printf("Service startup: OK.\n");
	}
	else
	{
		printf("Service startup: FAILD.\n");
		return false;
	}

	return true;
	
}


