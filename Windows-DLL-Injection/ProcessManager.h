#pragma once
#include <windows.h>
#include<string>

class ProcessManager
{
private:
	DWORD processID;
	HANDLE hProcess;
public:
	ProcessManager();
	~ProcessManager();
	bool AttachToProcess(const std::wstring& processName);
	//getters
	HANDLE GetHandle() const;
	DWORD GetPID() const;
};
