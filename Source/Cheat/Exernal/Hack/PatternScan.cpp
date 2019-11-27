#include "pch.h"
#include "PatternScan.h"

MemoryScanner::MemoryScanner(HANDLE hProcess, DWORD dwFlags): m_hProcess(hProcess), m_dwFlags(dwFlags), m_lowAddr(0), m_highAddr(0), m_bSafeSearch(false), m_bExtra(false), m_dwExtraCount(0)
{

}

MemoryScanner::MemoryScanner(HANDLE hProcess, DWORD dwFlags, uintptr_t LowAddr, uintptr_t HighAddr): m_hProcess(hProcess), m_dwFlags(dwFlags), m_lowAddr(LowAddr), m_highAddr(HighAddr), m_bSafeSearch(false), m_bExtra(false), m_dwExtraCount(0)
{
}

MemoryScanner::~MemoryScanner()
{
	m_hProcess = INVALID_HANDLE_VALUE;
	m_dwFlags = 0;
	m_lowAddr = 0;
	m_highAddr = 0;
	m_bSafeSearch = false;
	m_bExtra = false;
	m_dwExtraCount = 0;
}

void MemoryScanner::setSafeSearch(bool bSafe)
{
	m_bSafeSearch = bSafe;
}

void MemoryScanner::setExtraFlag(bool bExtra, DWORD dwExtraCount)
{
	m_bExtra = bExtra;
	m_dwExtraCount = dwExtraCount;
}

void MemoryScanner::setFlags(DWORD dwFlags)
{
	m_dwFlags = dwFlags;
}

DWORD_PTR MemoryScanner::scan(const MemoryPattern & memPattern) const
{
	SYSTEM_INFO sysINFO;
	GetSystemInfo(&sysINFO);

	PBYTE pCurAddr = (PBYTE)sysINFO.lpMinimumApplicationAddress;
	PBYTE pMaxAddr = (PBYTE)sysINFO.lpMaximumApplicationAddress;

	DWORD_PTR result = 0;
	MEMORY_BASIC_INFORMATION mbi;
	while (pCurAddr < pMaxAddr)
	{
		if (VirtualQueryEx(m_hProcess, pCurAddr, &mbi, sizeof(mbi)))
			if (processSectionScan(pCurAddr, memPattern, mbi, &result) == 1)
				break;
		pCurAddr += mbi.RegionSize;
	}
	return result;
}

DWORD_PTR MemoryScanner::processPatternScan(PBYTE pCurAddr, std::size_t uiSize, const MemoryPattern & memPattern) const
{
	std::vector<BYTE> vBuffer(uiSize);

	return 0;
}

int MemoryScanner::processSectionScan(PBYTE pCurAddr, const MemoryPattern & memPattern, MEMORY_BASIC_INFORMATION mbi, DWORD_PTR* pdwResult) const
{
	return 0;
}
