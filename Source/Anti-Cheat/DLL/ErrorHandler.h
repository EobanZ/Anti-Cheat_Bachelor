#pragma once
#include <string>
#include <Windows.h>
class ErrorHandler
{
public:
	static void errorMessage(std::string ErrorCode, int ErrorType);
	static void errorMessageW(std::wstring ErrorCode, int ErrorzType);
};

