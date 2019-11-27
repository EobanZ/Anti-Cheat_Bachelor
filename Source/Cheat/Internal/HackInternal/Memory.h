#pragma once
static class Memory
{
public:
	
	
	template<typename T>
	static T Read(uintptr_t address) {
		return *((T*)address);
	}

	template<typename T>
	static void Write(uintptr_t address, T value) {
		*((T*)address) = value;
	}

	template<typename T>
	static T* ReadPointer(uintptr_t address) {
		return ((T*)address);
	}

	template<typename T>
	static DWORD protectMemory(uintptr_t address, DWORD prot) {
		DWORD oldProt;
		VirtualProtect((LPVOID)address, sizeof(T), prot, &oldProt);
		return oldProt;
	}

	template<int SIZE>
	static void writeNop(uintptr_t address)
	{
		auto oldProtection = Memory::protectMemory<BYTE[SIZE]>(address, PAGE_EXECUTE_READWRITE);
		for (int i = 0; i < SIZE; i++)
		{
			Memory::Write<BYTE>(address + i, 0x90);
		}	
		Memory::protectMemory<BYTE[SIZE]>(address, oldProtection);
	}
	
	
};


