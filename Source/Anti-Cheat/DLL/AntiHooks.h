#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include "md5.h"


class AntiHooks
{

public:
	static bool Api_HookCheckModBounds();
	static bool IAT_HookCheck();
	static bool IAT_HookCheck2();
private:
	static bool Api_HookCheckModBoundsSingle(HMODULE dll, char * apiList);
	static bool IAT_HookCheckSingle(HMODULE dll, const char * apiList);
};

