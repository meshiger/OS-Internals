#pragma once
#include <windows.h>
#include <string>

class Injector
{
public:
	bool InjectStandard(HANDLE hProcess, const std::string& dllPath);
	bool InjectHijack(DWORD processID, HANDLE hProcess, const std::string& dllPath);
	bool InjectAPC(DWORD processID, HANDLE hProcess, const std::string& dllPath);
};
