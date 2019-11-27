#pragma once
#include <Windows.h>
#include <vector>
#include <string>

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation
} MEMORY_INFORMATION_CLASS;


class MemoryEnumeration
{
public:
	

	//MEMORY
	static char * PatternScan(char * pStart, UINT_PTR RegionSize, const char * szPattern, const char * szMask, int Len);
	static char * PatternScanEx(HANDLE hProc, char * pStart, UINT_PTR RegionSize, const char * szPattern, const char * szMask);

	//WINDOW
	static void EnumerateWindows(std::vector<std::string>* BlacklistedWindowNames);

	//PROCESS
	static void EnumerateProcesses(std::vector<std::wstring>* BlacklistedProcNames);

	//Images
	static void EnumerateImages(std::vector<std::string>* BlacklistedImageNames);

	//TCP Table
	static void EnumerateTcpTable(std::vector<std::string>* BlacklistedIpAddresses);
};

