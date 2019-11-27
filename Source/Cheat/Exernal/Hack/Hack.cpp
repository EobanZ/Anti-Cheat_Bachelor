// Hack.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//

#include <iostream>
#include "Memory.h"
#include "Utils.h"
#include <memory>
#include "DynamicWinAPI.h"

HWND Window; //Window of the process to hack
DWORD hackMePID = 0; //Process ID of the process to hack
HANDLE hProc = INVALID_HANDLE_VALUE; //Handle to the Process
HANDLE hThread = INVALID_HANDLE_VALUE; //Handle to the wanted Thread


#pragma region Thread Injection

typedef int(WINAPI * msgbox)(HWND, LPCSTR, LPCSTR, UINT); //Prototype for MsgBox()

void StartThreadInjection()
{
	BYTE codeCaveInjection[] = {
	0x68, 0x00, 0x00, 0x00, 0x00,							// PUSH 0 <-hier kommt der window type
	0x68, 0x00, 0x00, 0x00, 0x00,							// PUSH 0 <-hier kommt die addr des texts
	0x68, 0x00, 0x00, 0x00, 0x00,							// PUSH 0 <-hier kommt die addr des titels 
	0x68, 0x00, 0x00, 0x00, 0x00,							// PUSH 0 <-ist HSWN. Bleibt 0 da dann eigenes fenster des threads
	0xB8, 0x00, 0x00, 0x00, 0x00,							// MOV EAX, 0x0
	0xFF, 0xD0,												// CALL EAX
	0xC3													// RETN
	};
	//0x83, 0xC4, 0x10,										// ADD ESP, 0x10 (4Params -> 4bytes * 4) nicht da stdcall

	//Create Assembly Code Cave:
	const char* textString = "This process was Thread Injected";
	const char* titleString = "Thread Injected";
	const UINT* windowType = new UINT(MB_OK | MB_ICONINFORMATION);


	//Alloc Mem in remote process
	int stringlenText = strlen(textString) + 1; //+1 to include null terminator
	int stringlenTitle = strlen(titleString) + 1;
	int cavelen = sizeof(codeCaveInjection);
	int fulllen = stringlenText + stringlenTitle + cavelen;

	LPVOID remoteStringText = VirtualAllocEx(hProc, 0, fulllen, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //Allocate memory for the parameters and the codecove
	LPVOID remoteStringTitle = (LPVOID)((DWORD)remoteStringText + stringlenText); //keep a note of where the title string will go
	LPVOID remoteCave = (LPVOID)((DWORD)remoteStringText + stringlenText + stringlenTitle); //keep a note of where the code cave will go

	int tmpHwnd = 0;
	//Fill the Skeleton. Parameter von rechts nach links
	memcpy(&codeCaveInjection[1], windowType, 4); //Copy the adress of the remote text string in the skeleton
	memcpy(&codeCaveInjection[6], &remoteStringTitle, 4);
	memcpy(&codeCaveInjection[11], &remoteStringText, 4);
	memcpy(&codeCaveInjection[16], &tmpHwnd, 4);

	auto msgBoxAddr2 = GetProcAddress(LoadLibraryA("User32.dll"), "MessageBoxA");

	memcpy(&codeCaveInjection[21], &msgBoxAddr2, 4);

	//Write needed data to the remote memory
	WriteProcessMemory(hProc, remoteStringText, textString, stringlenText, NULL); //write the text string to the allocated memory in the process
	WriteProcessMemory(hProc, remoteStringTitle, titleString, stringlenTitle, NULL); //write the title string to the allocated memory in the process
	WriteProcessMemory(hProc, remoteCave, codeCaveInjection, cavelen, NULL); //write the code cave behind the string in the allocated memory


	//Use Thread Injection to Execute the Code Cave:
	//Create Thread Standard:
	//HANDLE thread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)remoteCave, NULL, NULL, NULL);

	////Create Thread Nt (Lowest Level in user Mode):
	HANDLE thread = INVALID_HANDLE_VALUE;
	WinAPITable->NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, 0, hProc, (LPTHREAD_START_ROUTINE)remoteCave, 0, 0, 0, 0, 0, 0); //Funktioniert genauso mit CreateThreadEx. Nt wird nur nicht so leicht detected

	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	VirtualFreeEx(hProc, remoteStringText, fulllen, MEM_RELEASE);

}




#pragma endregion

#pragma region Thread Hijacking
void StartThreadHijacking() 
{
	//Cave Skeleton:
	BYTE codeCaveHijacking[] = {
		0x60,							// PUSHAD //push general registers to the stack
		0x9C,							// PUSHFD //push EFLAGS to the stack
		0x68, 0x00, 0x00, 0x00, 0x00,	// PUSH 0 <-last param
		0x68, 0x00, 0x00, 0x00, 0x00,	// PUSH 0 <-param 3
		0x68, 0x00, 0x00, 0x00, 0x00,	// PUSH 0 <-param 2
		0x68, 0x00, 0x00, 0x00, 0x00,	// PUSH 0 <-fistr param
		0xB8, 0x00, 0x00, 0x00, 0x00,	// MOV EAX, 0x0 <-adress of message box
		0xFF, 0xD0,						// CALL EAX	
		0x9D,							// POPFD //pop EFLAGS from the stack
		0x61,							// POPAD //pop general registers from the stack
		0x68, 0x00, 0x00, 0x00, 0x00,	// PUSH 0 //un-hijack: resume the thread without using registers -> push originalEIP
		0xC3							// RETN
	};
	//0x83, 0xC4, 0x08,				// ADD ESP, 0x08

	//Params:
	const UINT* windowType = new UINT(MB_OK | MB_ICONINFORMATION);
	const char* titleString = "Hijacked Thread";
	const char* textString = "This thread was Hijacked";

	//allocate memory for the code cave and strings. Handle and Type are written dircetly into cave bcs their size is 4bytes
	int lenTitle = strlen(titleString) + 1;
	int lenText = strlen(textString) + 1;
	int cavelen = sizeof(codeCaveHijacking);
	int fullen = lenTitle + lenText + cavelen;

	LPVOID remoteTitleString = VirtualAllocEx(hProc, NULL, fullen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID remoteTextString = (LPVOID)((uintptr_t)remoteTitleString + lenTitle);
	LPVOID remoteCave = (LPVOID)((uintptr_t)remoteTitleString + lenTitle + lenText);

	//suspend the thread and query its control context
	std::vector<DWORD> threads = Utils::getProcessThreadIds(hackMePID);
	DWORD threadId = threads[0];

	HANDLE thread = OpenThread((THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT), false, threadId);
	SuspendThread(thread);

	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(thread, &threadContext); 
	
	//fill the Skeleton
	auto msgBoxAddr = GetProcAddress(LoadLibraryA("User32.dll"), "MessageBoxA");

	std::cout << "Original EIP: " << threadContext.Eip << std::endl;
	
	memcpy(&codeCaveHijacking[3], windowType, 4);
	memcpy(&codeCaveHijacking[8], &remoteTitleString, 4);
	memcpy(&codeCaveHijacking[13], &remoteTextString, 4);
	memcpy(&codeCaveHijacking[23], &msgBoxAddr, 4);
	memcpy(&codeCaveHijacking[32], &threadContext.Eip, 4);

	// write the code cave
	WriteProcessMemory(hProc, remoteTitleString, titleString, lenTitle, NULL);
	WriteProcessMemory(hProc, remoteTextString, textString, lenText, NULL);
	WriteProcessMemory(hProc, remoteCave, codeCaveHijacking, cavelen, NULL);


	//hijack the thread
	threadContext.Eip = (DWORD)remoteCave;
	threadContext.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(thread, &threadContext);
	std::cout << "EIP when resuming: " << threadContext.Eip << std::endl;
	ResumeThread(thread);
	

	//clean
	CloseHandle(thread);
	
}
#pragma endregion

#pragma region DllInjection
void StartDllInjectionViaRemoteThreadAndLoadLibrary() {
	//write dll name to the memory of the process
	const char* dllName = "IATHook.dll";
	int namelen = strlen(dllName) + 1;
	LPVOID remoteString = VirtualAllocEx(hProc, NULL, namelen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProc, remoteString, dllName, namelen, NULL);

	//get adress of LoadLibraryA()
	LPVOID loadLib = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

	//create thread
	HANDLE thread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLib, remoteString, NULL, NULL);

	//let the thread finish and clean up
	WaitForSingleObject(thread, INFINITE);
	VirtualFreeEx(hProc, remoteString, namelen, MEM_RELEASE);
	CloseHandle(thread);
}
#pragma endregion

#pragma region Overlay

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CLOSE:
		DestroyWindow(hwnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

bool CreateOverlay()
{
	//Find Window
	auto window = FindWindow(NULL, L"HackMe");

	//Get Rect
	RECT pos;
	GetWindowRect(window, &pos);

	int width = pos.right - pos.left;
	int height = pos.bottom - pos.top;
	//Start new Window on position
	DWORD style = WS_VISIBLE;
	DWORD styleEx = WS_EX_LAYERED | WS_EX_TRANSPARENT;

	WNDCLASSEX wc;
	HWND hwnd;
	MSG Msg;

	//Step 1: Registering the Window Class
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = WndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = GetModuleHandleA(NULL);
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = L"my_Winow_class";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

	if (!RegisterClassEx(&wc))
	{
		MessageBox(NULL, L"Window Registration Failed!", L"Error!",
			MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	// Step 2: Creating the Window
	hwnd = CreateWindowExW(
		styleEx,
		wc.lpszClassName,
		L"The title of my window",
		style,
		pos.left, pos.top, width, height,
		NULL, NULL, GetModuleHandleA(NULL), NULL);

	if (hwnd == NULL)
	{
		MessageBox(NULL, L"Window Creation Failed!", L"Error!",
			MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	ShowWindow(hwnd, 1);
	UpdateWindow(hwnd);

	// Step 3: The Message Loop
	while (GetMessage(&Msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&Msg);
		DispatchMessageW(&Msg);
	}
	return (int)Msg.wParam;
}
#pragma endregion

int main()
{
	//Create Dynamic WIN API:
	std::shared_ptr<DynamicWinapi> winAPIHelper = std::make_shared<DynamicWinapi>(); //Nicht umbedingt notwendig
	winAPIHelper->Initialize();

	//Set the Console Title
	SetConsoleTitle(L"External Cheat");

	//Window = FindWindow(NULL, L"HackMe"); //Find the window to hack
	//hackMePID = Utils::getProcessIdFromWindow(Window); //get the windows Process Id 

	hackMePID = Utils::getProcessIdByName(std::wstring(L"HackMe.exe"));
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hackMePID); //get a handle to the process 
	if (hProc == INVALID_HANDLE_VALUE)
		std::cout << "Failed to create HackMe Handle" << std::endl;
	
	//2 Different Methods to get the base Address of a Process
	//DWORD base = Utils::getBaseAdressWithCRT(hProc);
	//DWORD base2 = Utils::getModuleBaseAdress(hackMePID, L"HackMe.exe");

	
	//CreateOverlay();

	std::cout << "Bitte HackMe.exe starten und Injectionsverfahren waehlen: " << std::endl;
	std::cout << "1-> Thread Injection" << std::endl << "2-> Thread Hijacking" << std::endl;
	int wahl = -1;
	bool passt = false;
	std::cin >> wahl;

	while (passt == false)
	{
		

		switch (wahl)
		{
		case 1:
			std::cout << "Thread Injection started" << std::endl;
			StartThreadInjection();
			passt = true;
			break;
		case 2:
			std::cout << "Thread Injection started" << std::endl;
			StartThreadHijacking();
			passt = true;
			break;
		default:
			std::cout << "Ungueltige Eingabe" << std::endl;
			std::cout << "Bitte HackMe.exe starten und Cheat waehlen: " << std::endl;
			std::cin >> wahl;
			break;
		}


	}
	
	//StartThreadInjection(); 
	//StartThreadHijacking(); 
	//StartDllInjectionViaRemoteThreadAndLoadLibrary(); 

	getchar();

}


