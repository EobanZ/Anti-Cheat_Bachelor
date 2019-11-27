#pragma once
#include <Windows.h> 
#include <string>
#include <vector>


class MemoryPattern
{
public:
	MemoryPattern(LPCVOID c_lpPattern, const char* c_szMask, DWORD dwPatternOffset, DWORD dwAddroffset);
	~MemoryPattern();
	std::size_t getLenght() const;
	DWORD getPatternOffset() const;
	DWORD getAddrOffset() const;

	char getMask(std::size_t uiIndex) const;
	const char* getMask() const;

	BYTE getByte(std::size_t uiIndex) const;
	LPCVOID getBytes() const;

private:
	const char* m_cszMask;
	LPCVOID m_lpPattern;

	DWORD m_dwPatternOffset;
	DWORD m_dwAddrOffset;

	std::vector <std::pair<char, BYTE> > m_vPattern;
	

};

