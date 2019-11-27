#pragma once
#include "DriverIO.h"
#include <Windows.h>
#include <iostream>
class DriverIORequests
{
public:
	static bool SendProcesses(HANDLE hDriver,PKERNEL_PROCESS_INFO pProcesses);
	static bool SendSystemProcesses(HANDLE hDriver, PKERNEL_SYSTEMPROCESS_INFO pSysProcesses);
};

