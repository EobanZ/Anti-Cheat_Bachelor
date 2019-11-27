#pragma once
class Utils
{
public:
	
	static uintptr_t getMyBaseAddress();

	static PVOID hookFunc(BYTE* src, const BYTE* dst, const int len);

	static uintptr_t findPattern(uintptr_t address, DWORD len, BYTE* pattern, const char* mask); //Untested

	static DWORD getThreadOwnerProcessId(DWORD threadID);
};

