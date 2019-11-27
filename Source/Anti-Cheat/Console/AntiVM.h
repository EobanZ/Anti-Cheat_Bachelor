#pragma once
#include <Windows.h>
#include <string>
#include "Utils.h"
class AntiVM
{
public:
	static bool CheckLoadedDLLs();
	static bool CheckRegKeys();
	static bool CheckDevices();
	static bool CheckWindows();
	static bool CheckProcesses();
};

