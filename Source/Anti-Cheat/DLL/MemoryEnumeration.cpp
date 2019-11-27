#pragma once
#include "MemoryEnumeration.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "ErrorHandler.h"
#include <iphlpapi.h>
#include <algorithm>

bool __fastcall INT_ComparePattern2(char * szSource, const char * szPattern, const char * szMask)
{
	while (*szMask)
	{
		if (*szMask <= '9')
		{
			szPattern += ((*szMask) ^ 0x30);
			szSource += ((*szMask) ^ 0x30);
		}
		else
		{
			for (int i = ((*szMask) ^ 0x60); i; --i)
				if (*(szSource++) != *(szPattern++))
					return false;
		}
		++szMask;
	}

	return true;
}

bool INT_ComparePattern(char * szSource, const char * szPattern, const char * szMask)
{
	for (; *szMask; ++szSource, ++szPattern, ++szMask)
		if (*szMask == 'x' && *szSource != *szPattern)
			return false;

	return true;
}

char * INT_PatternScan(char * pData, UINT_PTR RegionSize, const char * szPattern, const char * szMask, int Len)
{
	for (UINT i = 0; i != RegionSize - Len; ++i, ++pData)
		if (INT_ComparePattern(pData, szPattern, szMask))
			return pData;

	return nullptr;
}

char * MemoryEnumeration::PatternScan(char * pStart, UINT_PTR RegionSize, const char * szPattern, const char * szMask, int Len)
{
	char * pCurrent = pStart;

	while (pCurrent <= pStart + RegionSize - Len)
	{
		MEMORY_BASIC_INFORMATION MBI{ 0 };
		if (!VirtualQuery(pCurrent, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
			return nullptr;

		if (MBI.State == MEM_COMMIT && !(MBI.Protect & PAGE_NOACCESS || MBI.Protect & PAGE_GUARD))
		{
			if (pCurrent + MBI.RegionSize > pStart + RegionSize - Len)
				MBI.RegionSize = pStart + RegionSize - pCurrent + Len;

			char * Ret = INT_PatternScan(pCurrent, MBI.RegionSize, szPattern, szMask, Len);

			if (Ret && (Ret!=szPattern))
				return Ret;
		}
		pCurrent += MBI.RegionSize; 
	}

	return nullptr;
}

char * MemoryEnumeration::PatternScanEx(HANDLE hProc, char * pStart, UINT_PTR RegionSize, const char * szPattern, const char * szMask)
{
	DWORD Buffer = 0;
	if (!GetHandleInformation(hProc, &Buffer))
		return nullptr;

	char * pCurrent = pStart;
	auto Len = lstrlenA(szMask);

	SIZE_T BufferSize = 0x10000;
	char * Data = new char[BufferSize];

	while (pCurrent <= pStart + RegionSize - Len)
	{
		MEMORY_BASIC_INFORMATION MBI{ 0 };
		if (!VirtualQueryEx(hProc, pCurrent, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
			return nullptr;

		if (MBI.State == MEM_COMMIT && !(MBI.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		{
			if (BufferSize < MBI.RegionSize)
			{
				delete[] Data;
				BufferSize = MBI.RegionSize;
				Data = new char[BufferSize];
			}

			UINT_PTR Delta = pCurrent - reinterpret_cast<char*>(MBI.BaseAddress);
			MBI.RegionSize -= Delta;

			if (pCurrent + MBI.RegionSize > pStart + RegionSize - Len)
				MBI.RegionSize -= pCurrent + MBI.RegionSize - pStart - RegionSize + Len;

			if (!ReadProcessMemory(hProc, pCurrent, Data, MBI.RegionSize, nullptr))
			{
				pCurrent = pCurrent + MBI.RegionSize;
				continue;
			}

			char * Ret = INT_PatternScan(Data, MBI.RegionSize, szPattern, szMask, Len);

			if (Ret)
			{
				delete[] Data;
				return (Ret - Data + pCurrent);
			}
		}

		pCurrent = pCurrent + MBI.RegionSize;
	}

	delete[] Data;

	return nullptr;
}

void MemoryEnumeration::EnumerateWindows(std::vector<std::string>* BlacklistedWindowNames)
{

	int windowCount = 0;
	for (auto window_handle = GetTopWindow(NULL); window_handle; window_handle = GetWindow(window_handle, GW_HWNDNEXT), windowCount++)
	{
		DWORD window_process_pid = 0;
		GetWindowThreadProcessId(window_handle, &window_process_pid);

		if (window_process_pid == GetCurrentProcessId()) //Ignore own process
			continue;

		constexpr auto max_character_count = 0x80;
		char title[max_character_count];
		const auto length = GetWindowTextA(window_handle, title, max_character_count);

		std::string s = std::string(title);
		
		for (auto name : *BlacklistedWindowNames)
		{
			if (s.find(name) != std::string::npos)
			{
				//REPORT
				printf_s("Found Cheat Window\n");
				printf_s("%s \n", s.c_str());
				ErrorHandler::errorMessage("Found Cheat Window", 2);
			}
		}
		
	}

	//Window Anumaly
	if (windowCount <= 1)
		printf_s("Window anomaly found \n");
		//Report: Probably hooked
}

void MemoryEnumeration::EnumerateProcesses(std::vector<std::wstring>* BlacklistedProcNames)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			std::wstring binaryPath = entry.szExeFile;
			for (auto name : *BlacklistedProcNames)
			{
				if (binaryPath.find(name) != std::string::npos)
				{
					//REPORT: found blacklisted process name
					ErrorHandler::errorMessage("Blacklisted process found", 4);
				}
			}

		}
	}

	CloseHandle(snapshot);
}

void MemoryEnumeration::EnumerateImages(std::vector<std::string>* BlacklistedImageNames)
{
	for (auto imgName : *BlacklistedImageNames)
	{
		auto module_handle = GetModuleHandleA(imgName.c_str());
		if (module_handle)
		{
			//REPORT: Blacklisted DLL Image found
			printf_s("Blacklisted loaded image found");
			ErrorHandler::errorMessage("Blacklisted loaded image found", 4);
		}
	}
}

void MemoryEnumeration::EnumerateTcpTable(std::vector<std::string>* BlacklistedIpAddresses)
{
	std::vector<std::string> FoundIps;

	// GET NECESSARY SIZE OF TCP TABLE
	DWORD table_size = 0;
	GetExtendedTcpTable(0, &table_size, false, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);

	// ALLOCATE BUFFER OF PROPER SIZE FOR TCP TABLE
	auto allocated_ip_table = (MIB_TCPTABLE_OWNER_MODULE*)malloc(table_size);

	if (GetExtendedTcpTable(allocated_ip_table, &table_size, false, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) != NO_ERROR)
		goto cleanup;

	for (int entry_index = 0; entry_index < allocated_ip_table->dwNumEntries; ++entry_index)
	{
		for (auto blAddr : *BlacklistedIpAddresses)
		{
			unsigned long ip = inet_addr(blAddr.c_str()); //convert ip to right format
			if (allocated_ip_table->table[entry_index].dwRemoteAddr == ip)
			{
				//REPORT: Blacklisted Ip found
				FoundIps.push_back(blAddr);
			}
		}
	}

	if (!FoundIps.empty())
	{
		auto last = std::unique(FoundIps.begin(), FoundIps.end());
		FoundIps.erase(last, FoundIps.end());

		for (size_t i = 0; i < FoundIps.size(); i++)
		{
			printf_s("Client connected to a cheat website. IP: %s \n", FoundIps.at(i).c_str());
		}
	}
	


cleanup:
	free(allocated_ip_table);
	
}

