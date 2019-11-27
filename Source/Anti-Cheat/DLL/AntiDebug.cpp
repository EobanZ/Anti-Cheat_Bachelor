#include "AntiDebug.h"
#include <vector>
#include <random>

#pragma region stack overflow
typedef void(*_recurse)();
void recurse1(); void recurse2();
void recurse3(); void recurse4();
void recurse5();
_recurse recfuncs[5] = {
&recurse1, &recurse2, &recurse3,
&recurse4, &recurse5
};
void recurse1() { recfuncs[rand() % 5](); }
void recurse2() { recfuncs[(rand() % 3) + 2](); }
void recurse3() {
	if (rand() % 100 < 50) recurse1();
	else recfuncs[(rand() % 3) + 1]();
}
void recurse4() { recfuncs[rand() % 2](); }
void recurse5() {
	for (int i = 0; i < 100; i++)
		if (rand() % 50 == 1)
			recfuncs[i % 5]();
	recurse5();
}
#pragma endregion




bool AntiDebug::hideThread(HANDLE hThread)
{
	typedef NTSTATUS(NTAPI *pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	// Get NtSetInformationThread
	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
			"NtSetInformationThread");

	// Shouldn't fail
	if (NtSIT == NULL)
		return false;

	// Set the thread info
	if (hThread == NULL)
		Status = NtSIT(GetCurrentThread(),
			0x11, // HideThreadFromDebugger
			0, 0);
	else
		Status = NtSIT(hThread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}

bool AntiDebug::isDebuggerPresentAPI()
{
	return IsDebuggerPresent();
}

bool AntiDebug::checkRemoteDebuggerPresentAPI()
{
	BOOL dbg = false;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
	return dbg;
}

bool AntiDebug::canCallOutputDebugString()
{
	SetLastError(0);
	OutputDebugStringA("test");
	//return (GetLastError() == 0);
	return false;
}

bool AntiDebug::hasRIPExceptionHandler()
{
	__try { RaiseException(0x40010007, 0, 0, 0); }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
	return true;
}

bool AntiDebug::memoryBreakpoints_PageGuard()
{
	UCHAR *pMem = NULL;
	SYSTEM_INFO SystemInfo = { 0 };
	DWORD OldProtect = 0;
	PVOID pAllocation = NULL; // Get the page size for the system 

							  // Retrieves information about the current system.
	GetSystemInfo(&SystemInfo);

	// Allocate memory 
	pAllocation = VirtualAlloc(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pAllocation == NULL)
		return FALSE;

	// Write a ret to the buffer (opcode 0xc3)
	RtlFillMemory(pAllocation, 1, 0xC3);

	// Make the page a guard page         
	if (VirtualProtect(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
		return FALSE;

	__try
	{
		((void(*)())pAllocation)(); // Exception or execution, which shall it be :D?
	}
	__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		VirtualFree(pAllocation, NULL, MEM_RELEASE);
		return FALSE;
	}

	VirtualFree(pAllocation, NULL, MEM_RELEASE);
	return TRUE;
}


bool AntiDebug::sharedUserData_KernelDebugger()
{
	const ULONG_PTR UserSharedData = 0x7FFE0000;

	const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4);

	const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
	const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2 == 0);

	if (KdDebuggerEnabled || !KdDebuggerNotPresent)
		return true;

	return false;
}

bool AntiDebug::has2DBreakpointHandler()
{
	__try { __asm INT 0x2D }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
	return true;

}

bool AntiDebug::has03BreakpointHandler()
{
	__try { __asm INT 0x03 }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
	return true;
}

bool AntiDebug::hasHardwareBreakpoints()
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	auto hThread = GetCurrentThread();
	if (GetThreadContext(hThread, &ctx) == 0)
		return false;
	return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

bool AntiDebug::debuggerDriversPresent()
{
	// an array of common debugger driver device names
	const char drivers[9][20] = {
			"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
			"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
			"\\\\.\\SIWVID", "\\\\.\\SYSER",
			"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
			"\0"
	};

	for (int i = 0; drivers[i][0] != '\0'; i++)
	{
		auto h = CreateFileA(drivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h);
			return true;
		}
	}
	return false;
}




void AntiDebug::crashOllyDbg()
{
	OutputDebugStringA("%s%s%s%s");
}

void AntiDebug::startInfLoop()
{
	std::vector<char*> explosion;
	while (true)
		explosion.push_back(new char[10000]);
}

void AntiDebug::startStackOverflow()
{
	recurse1();
}

void AntiDebug::startBSOD()
{
	typedef long (WINAPI *RtlSetProcessIsCritical)
		(BOOLEAN New, BOOLEAN *Old, BOOLEAN NeedScb);
	auto ntdll = LoadLibraryA("ntdll.dll");
	if (ntdll) {
		auto SetProcessIsCritical = (RtlSetProcessIsCritical)
			GetProcAddress(ntdll, "RtlSetProcessIsCritical");
		if (SetProcessIsCritical)
			SetProcessIsCritical(1, 0, 0);
	}
}





