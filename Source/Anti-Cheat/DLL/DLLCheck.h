#pragma once
#include "DLLInjectDetector.h"
#include "Utils.h"
#include <Windows.h>
#include <iostream>
#include <assert.h>
#include <Psapi.h>
#include <algorithm>
#include <TlHelp32.h>
#include "ErrorHandler.h"

typedef ULONG(NTAPI* RtlGetFullPathName_U)(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);
static RtlGetFullPathName_U RtlGetFullPathName_U_ = nullptr;

class DLLCheck
{
public:
	static void InitializeDLLCheck();

	static ULONG NTAPI RtlGetFullPathName_U_t(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);

};

