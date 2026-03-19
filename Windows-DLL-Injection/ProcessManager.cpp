#include "ProcessManager.h"
#include <tlhelp32.h>
#include <iostream>

/*
 * Default constructor for ProcessManager.
 * Initializes the process ID and handle to default safe values.
 */
ProcessManager::ProcessManager()
{
	processID = 0;
	hProcess = NULL;
}

/*
 * Destructor for ProcessManager.
 * Implements the RAII pattern. Automatically closes the target process handle
 * when the object goes out of scope, preventing resource and handle leaks.
 */
ProcessManager::~ProcessManager()
{
	if (hProcess)
		CloseHandle(hProcess);
}

/*
 * Retrieves the handle to the attached process.
 * output: HANDLE The opened handle to the target process (with PROCESS_ALL_ACCESS).
 */
HANDLE ProcessManager::GetHandle() const
{
	return hProcess;
}

/*
 * Retrieves the Process ID (PID) of the attached process.
 * output: DWORD The target process identifier.
 */
DWORD ProcessManager::GetPID() const
{
	return processID;
}

/*
 * Attaches to a target process by its executable name.
 * Takes a snapshot of all running processes, iterates through them to find
 * a match (case-insensitive), and attempts to open a handle with full privileges.
 * input: processName The name of the target executable (e.g., L"mspaint.exe").
 * output: true if the process was found and successfully opened, false otherwise.
 */
bool ProcessManager::AttachToProcess(const std::wstring& processName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;

	if (hSnap == INVALID_HANDLE_VALUE)
		return false;

	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnap, &pe))
	{
		do
		{
			// Case-insensitive comparison of the executable name
			if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0)
				processID = pe.th32ProcessID;
		} while ((Process32Next(hSnap, &pe)) && (processID == 0));
	}

	CloseHandle(hSnap);

	// If the PID was found, attempt to open a handle to the process
	if (processID)
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		if (hProcess)
			return true;
	}

	return false;
}