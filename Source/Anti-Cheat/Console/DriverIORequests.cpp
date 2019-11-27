#include "DriverIORequests.h"

bool DriverIORequests::SendProcesses(HANDLE hDriver, PKERNEL_PROCESS_INFO pProcesses)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return false;

	return DeviceIoControl(hDriver, IO_SEND_PROCESSES, pProcesses, sizeof(KERNEL_PROCESS_INFO), pProcesses, sizeof(KERNEL_PROCESS_INFO), 0, NULL);
}

bool DriverIORequests::SendSystemProcesses(HANDLE hDriver, PKERNEL_SYSTEMPROCESS_INFO pSysProcesses)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return false;

	return DeviceIoControl(hDriver, IO_SEND_SYSTEMPROCESSES, pSysProcesses, sizeof(KERNEL_SYSTEMPROCESS_INFO), pSysProcesses, sizeof(KERNEL_SYSTEMPROCESS_INFO), 0, NULL); 
}


