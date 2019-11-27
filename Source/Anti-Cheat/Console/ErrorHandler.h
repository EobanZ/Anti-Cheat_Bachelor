#pragma once
#include <string>
#include <Windows.h>
#include "Service.h"


extern CService* service; 
static class ErrorHandler
{
private:

public:
	static void setService(CService* pService);
	static void errorMessage(std::string ErrorCode, int ErrorType);
	static bool unloadDriver();
	static bool unloadDriver(const char* DriverName);
	static bool loadDriver();
};

