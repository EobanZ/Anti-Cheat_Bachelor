#pragma once
#include <Windows.h>
#include "md5.h"
class Utils
{
public:
	static bool isSuspendedThread(DWORD dwThreadId);
	static PVOID DetourFunc(BYTE* src, const BYTE* dst, const int len);
	static bool IsLoadedAddress(DWORD dwAddress);
	static DWORD GetThreadOwnerProcessId(DWORD dwThreadID);
	static PVOID GetModuleAddressFromName(const wchar_t* c_wszName);
	static DWORD GetProcessID(const wchar_t* ExeName);
	static bool GetModuleMD5(std::string& result);
	static bool GetFileMD5(std::string& result);
	static bool isSuspendedThread2(DWORD dwThreadID);


	
};

