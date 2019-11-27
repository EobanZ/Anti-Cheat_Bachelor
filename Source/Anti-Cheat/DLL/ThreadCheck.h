#pragma once
#include "DLLInjectDetector.h"
#include "Utils.h"
#include <Windows.h>
#include <iostream>
#include <assert.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "ErrorHandler.h"



typedef void(*LdrInitializeThunk)(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
static LdrInitializeThunk LdrInitializeThunk_ = nullptr;

#define NtCurrentProcess			((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread				((HANDLE)(LONG_PTR)-2)


class ThreadCheck
{
public:
	static void InitializeThreadCheck();
	static void LdrInitializeThunk_t(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

};

