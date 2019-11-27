#pragma once
#include "Memory.h"
static class Hooks
{
public:
	
	static uintptr_t callHook(uintptr_t hookAt, uintptr_t newFunc);
	static uintptr_t hookIAT(const char* functionName, uintptr_t newFuctionAddress);
	static uintptr_t hookVF(uintptr_t classInst, DWORD funcIndex, uintptr_t newFunc);
	static uintptr_t hookJmp(uintptr_t hookAt, uintptr_t newFunc, int size);
};

