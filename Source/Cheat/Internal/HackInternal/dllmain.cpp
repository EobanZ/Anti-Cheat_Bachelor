// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.
#include "stdafx.h"
#include <iostream>
#include "Memory.h"
#include "Utils.h"
#include <Psapi.h>
#include "Hooks.h"


typedef Memory mem;


DWORD modSize = 0;
uintptr_t modBaseAddr = 0;


#pragma region Call Hook

typedef void(__thiscall* _orgFunc)(void*, int arg);
_orgFunc oPlayerDamage;

void __fastcall hPlayerDamage(void* This, void* edx, int arg)
{
	arg = -100;
	return oPlayerDamage(This, arg);
}

void callHookExample() {
	
	uintptr_t OriginalFunctionCallOffset = 0x00001EBF; //HackMe.exe+1EBF
	
	//Add Hook:
	oPlayerDamage = (_orgFunc) Hooks::callHook(modBaseAddr + OriginalFunctionCallOffset, (uintptr_t)&hPlayerDamage);
}

#pragma endregion

#pragma region IAT Hook
typedef VOID(WINAPI* _origSleep)(DWORD ms);
_origSleep originalSleep;

VOID WINAPI newSleepFunction(DWORD ms)
{
	
	if (ms == (DWORD)1337) {
		printf("Sleep hook worked! \n");
	}		
	originalSleep(ms);
}

void IATHookExample() {
	originalSleep = (_origSleep)Hooks::hookIAT("Sleep", (uintptr_t)&newSleepFunction);
}


#pragma endregion

#pragma region VF Hook
typedef int(__thiscall* vfToHook)(void*, int arg1);
vfToHook oVirtualFunction;
// Addr for Assembly
// uintptr_t originalVFunction;
int __fastcall someNewVFFunction(void* This, void* edx, int arg1) {

	printf_s("Real Arg: %i \n", arg1);
	arg1 = 1;
	printf_s("New Arg: %i \n", arg1);

	return oVirtualFunction(This, arg1);


	//Via Assebly:
	//static uintptr_t /*_this,*/ _ret;
	//__asm MOV _this, ECX //safe instance address

	//__asm {
	//	PUSH 1 //pushes our own argument on the stack
	//	MOV ECX, _this
	//	CALL [originalVFunction]
	//	MOV _ret, EAX //return value is stored in EAX Register
	//}

	////__asm MOV ECX, _this //restore instance address
	//return _ret;
}

void VFHookExample() {
	
	uintptr_t playerInstanceOffset = 0x7078; 

	oVirtualFunction = (vfToHook)Hooks::hookVF((uintptr_t)modBaseAddr + playerInstanceOffset, 0, (uintptr_t)&someNewVFFunction);

}

#pragma endregion

#pragma region Jump Hook

void jumpHookCallback(uintptr_t EDI, uintptr_t ESI, uintptr_t EBP, uintptr_t ESP, uintptr_t EBX, uintptr_t EDX, uintptr_t ECX, uintptr_t EAX)
{
	ECX = 999;
}

uintptr_t restoreJumpHook = 0;
void __declspec(naked) myTrampoline()
{
	__asm {
		PUSHFD
		PUSHAD
		MOV EAX, jumpHookCallback  //Wenn zuvor in register geladen kann Adresse anstatt Offset verwendet werden
		CALL EAX 
		POPAD
		POPFD
		MOV EDX, [EBP-8]   //wurde vom original mit ins trampolin genommen
		JMP [restoreJumpHook]
	}
}


void JmpHookExample() 
{
	uintptr_t offset = 0x00002253; //SUB ECX,01
	restoreJumpHook = Hooks::hookJmp(modBaseAddr + offset, (uintptr_t)&myTrampoline, 6);  
}
#pragma endregion




DWORD WINAPI runHack(LPVOID lpParam) {

	std::cout << "Cheat is running from insisde" << std::endl;
	//Get Module Information
	MODULEINFO modinfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);
	modBaseAddr = (uintptr_t)hModule;
	HANDLE hProc = GetCurrentProcess();
	DWORD procBaseAddr = (DWORD)hProc;
	GetModuleInformation(hProc, hModule, &modinfo, sizeof(MODULEINFO));
	modSize = modinfo.SizeOfImage;
	CloseHandle(hProc);

	

	//Hook Examples. Uncomment to test
	//callHookExample();
	//IATHookExample();
	//VFHookExample();
	//JmpHookExample();

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "DLL Attached!\n", "Game Hacking", MB_OK | MB_TOPMOST);
		CreateThread(NULL, 0, &runHack, NULL, 0, NULL);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

