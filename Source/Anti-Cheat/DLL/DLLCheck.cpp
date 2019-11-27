#include "DLLCheck.h"
#include "ErrorHandler.h"
#include <vector>

void DLLCheck::InitializeDLLCheck()
{
	auto hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll)
	{
		auto hNtdll = LoadLibraryA("ntdll.dll");
		assert(hNtdll);

		auto RtlGetFullPathName_U_o = reinterpret_cast<RtlGetFullPathName_U>(GetProcAddress(hNtdll, "RtlGetFullPathName_U"));
		assert(RtlGetFullPathName_U_o);

		RtlGetFullPathName_U_ = reinterpret_cast<RtlGetFullPathName_U>(Utils::DetourFunc(reinterpret_cast<PBYTE>(RtlGetFullPathName_U_o), reinterpret_cast<PBYTE>(RtlGetFullPathName_U_t), 5));

		DWORD dwOld = 0;
		auto bProtectRet = VirtualProtect(RtlGetFullPathName_U_, 5, PAGE_EXECUTE_READWRITE, &dwOld);
		assert(bProtectRet);
	}
	else
	{
		ErrorHandler::errorMessage("0x4015 ( Please Restart )", 5);
	}
}



ULONG DLLCheck::RtlGetFullPathName_U_t(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR * ShortName)
{
	//printf("RtlGetFullPathName_U_t -> %ls - %u\n", FileName, Size);
	std::vector<std::wstring> whitelist;
	whitelist.push_back(L"NvCameraWhitelisting32.dll");

	auto pModuleBase = Utils::GetModuleAddressFromName(FileName);
	if (pModuleBase)
	{
		printf("Injected dll detected! Base: %p\n", pModuleBase);
		std::wstring Output = L"Injected DLL detected: ";
		Output.append(FileName);
	
		for (auto name : whitelist)
		{
			if(Output.find(name) == std::string::npos) //Check the found DLL is not in the whitelist
				ErrorHandler::errorMessageW(Output, 4);
		}
		
	}
		
		

	return RtlGetFullPathName_U_(FileName, Size, Buffer, ShortName);
}
