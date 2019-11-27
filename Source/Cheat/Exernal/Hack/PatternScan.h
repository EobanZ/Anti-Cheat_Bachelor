#pragma once
#include <Windows.h>
#include "PatternTemplate.h"

enum EScanFlags
{
	MEM_SCAN_NORMAL = (1 << 0), // normal
	MEM_SCAN_READ = (1 << 1), // rpm at pattern
	MEM_SCAN_SUBTRACT = (1 << 2), // subtract img base
	MEM_SCAN_WITHEXTRA = (1 << 3), // add extra data
};

class MemoryScanner
{
public:
	MemoryScanner(HANDLE hProcess, DWORD dwFlags);
	MemoryScanner(HANDLE hProcess, DWORD dwFlags, uintptr_t LowAddr, uintptr_t HighAddr);
	~MemoryScanner();

	void setSafeSearch(bool bSafe);
	void setExtraFlag(bool bExtra, DWORD dwExtraCount = 0);
	void setFlags(DWORD dwFlags);

	DWORD_PTR scan(const MemoryPattern& memPattern) const;

protected:
	DWORD_PTR processPatternScan(PBYTE pCurAddr, std::size_t uiSize, const MemoryPattern& memPattern) const;
	int processSectionScan(PBYTE pCurAddr, const MemoryPattern& memPattern, MEMORY_BASIC_INFORMATION mbi, DWORD_PTR* pdwResult) const;

private:
	HANDLE m_hProcess;

	uintptr_t m_lowAddr;
	uintptr_t m_highAddr;

	bool m_bSafeSearch;
	bool m_bExtra;

	DWORD m_dwFlags;
	DWORD m_dwExtraCount;

};

