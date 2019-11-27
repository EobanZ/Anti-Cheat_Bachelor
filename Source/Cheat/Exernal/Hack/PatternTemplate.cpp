#include "pch.h"
#include "PatternTemplate.h"


MemoryPattern::MemoryPattern(LPCVOID c_lpPattern, const char * c_szMask, DWORD dwPatternOffset, DWORD dwAddroffset) : m_vPattern(strlen(c_szMask)), m_lpPattern(c_lpPattern), m_cszMask(c_szMask), m_dwPatternOffset(dwPatternOffset), m_dwAddrOffset(dwAddroffset)
{
	for (std::size_t i = 0; i < m_vPattern.size(); i++)
	{
		m_vPattern[i].first = c_szMask[i];
		m_vPattern[i].second = reinterpret_cast<const BYTE*>(c_lpPattern)[i];
	}
}

MemoryPattern::~MemoryPattern()
{
	m_vPattern.clear();

	m_lpPattern = nullptr;
	m_cszMask = nullptr;

	m_dwPatternOffset = 0;
	m_dwAddrOffset = 0;
}

std::size_t MemoryPattern::getLenght() const
{
	return m_vPattern.size();
}

DWORD MemoryPattern::getPatternOffset() const
{
	return m_dwPatternOffset;
}

DWORD MemoryPattern::getAddrOffset() const
{
	return m_dwAddrOffset;
}

char MemoryPattern::getMask(std::size_t uiIndex) const
{
	return m_vPattern.at(uiIndex).first;
}

const char * MemoryPattern::getMask() const
{
	return m_cszMask;
}

BYTE MemoryPattern::getByte(std::size_t uiIndex) const
{
	return m_vPattern.at(uiIndex).second;
}

LPCVOID MemoryPattern::getBytes() const
{
	return m_lpPattern;
}
