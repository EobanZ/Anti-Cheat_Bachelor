#pragma once
#include <Windows.h>
#include <psapi.h>
class AntiDebug
{
public:
	static bool hideThread(HANDLE hThread);
	static bool isDebuggerPresentAPI();
	static bool checkRemoteDebuggerPresentAPI();
	static bool canCallOutputDebugString();
	static bool has2DBreakpointHandler();
	static bool has03BreakpointHandler();
	static bool hasHardwareBreakpoints();
	static bool hasRIPExceptionHandler();
	static bool memoryBreakpoints_PageGuard();
	static bool sharedUserData_KernelDebugger();
	static bool debuggerDriversPresent();

	//
	static void crashOllyDbg();
	static void startInfLoop();
	static void startStackOverflow();
	static void startBSOD();




};

