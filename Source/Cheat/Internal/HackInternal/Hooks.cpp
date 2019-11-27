#include "stdafx.h"
#include "Hooks.h"


uintptr_t Hooks::callHook(uintptr_t hookAt, uintptr_t newFunc)
{
	uintptr_t newOffset = newFunc - hookAt - 5;

	auto oldProtection = Memory::protectMemory<uintptr_t>(hookAt + 1, PAGE_EXECUTE_READWRITE);

	uintptr_t originalOffset = Memory::Read<uintptr_t>(hookAt + 1);
	Memory::Write<uintptr_t>(hookAt + 1, newOffset);
	Memory::protectMemory<uintptr_t>(hookAt + 1, oldProtection);

	return originalOffset + hookAt + 5;

}

uintptr_t Hooks::hookIAT(const char * functionName, uintptr_t newFuctionAddress)
{
	uintptr_t baseAddress = (uintptr_t)GetModuleHandle(NULL);

	auto dosHeader = Memory::ReadPointer<IMAGE_DOS_HEADER>(baseAddress);
	if (dosHeader->e_magic != 0x5A4D)
		return 0;

	auto optHeader = Memory::ReadPointer<IMAGE_OPTIONAL_HEADER>(baseAddress + dosHeader->e_lfanew + 24);
	if (optHeader->Magic != 0x10B)
		return 0;

	if (optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 ||
		optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
		return 0;

	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = Memory::ReadPointer<IMAGE_IMPORT_DESCRIPTOR>(baseAddress + optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (importDescriptor->FirstThunk)
	{
		int n = 0;
		IMAGE_THUNK_DATA* thunkData = Memory::ReadPointer<IMAGE_THUNK_DATA>(baseAddress + importDescriptor->OriginalFirstThunk);
		while (thunkData->u1.Function)
		{
			char* importFunctionName = Memory::ReadPointer<char>(baseAddress + (uintptr_t)thunkData->u1.AddressOfData + 2);
			if (strcmp(importFunctionName, functionName) == 0)
			{
				auto vfTable = Memory::ReadPointer<uintptr_t>(baseAddress + importDescriptor->FirstThunk);

				uintptr_t original = vfTable[n];

				auto oldProtection = Memory::protectMemory<uintptr_t>((uintptr_t)&vfTable[n], PAGE_READWRITE);
				vfTable[n] = newFuctionAddress;
				Memory::protectMemory<uintptr_t>((uintptr_t)&vfTable[n], oldProtection);

				return original;
			}

			n++;
			thunkData++;
		}
		importDescriptor++;
	}

	return 0;
}

uintptr_t Hooks::hookVF(uintptr_t classInst, DWORD funcIndex, uintptr_t newFunc)
{
	uintptr_t VFTable = Memory::Read<uintptr_t>(classInst);
	uintptr_t hookAddress = VFTable + funcIndex * sizeof(uintptr_t);

	auto oldProtection = Memory::protectMemory<uintptr_t>(hookAddress, PAGE_READWRITE);
	uintptr_t originalFunc = Memory::Read<uintptr_t>(hookAddress);
	Memory::Write<uintptr_t>(hookAddress, newFunc);
	Memory::protectMemory<uintptr_t>(hookAddress, oldProtection);

	return originalFunc;
}

uintptr_t Hooks::hookJmp(uintptr_t hookAt, uintptr_t newFunc, int size)
{
	if (size > 12) // shouldn't ever have to replace 12+ bytes
		return 0;
	uintptr_t newOffset = newFunc - hookAt - 5;

	auto oldProtection = Memory::protectMemory<uintptr_t[3]>(hookAt, PAGE_EXECUTE_READWRITE);
	Memory::Write<BYTE>(hookAt, 0xE9);
	Memory::Write<uintptr_t>(hookAt + 1, newOffset);
	for (unsigned int i = 5; i < size; i++)
		Memory::Write<BYTE>(hookAt + i, 0x90);
	Memory::protectMemory<uintptr_t[3]>(hookAt, oldProtection);

	return hookAt + 5;
}
