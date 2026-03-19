#include <iostream>
#include <string>
#include <windows.h>
#include "ProcessManager.h"
#include "Injector.h"

int main()
{
    std::wstring targetProcess = L"notepad.exe";
    std::string dllPath = "C:\\Path\\To\\Your\\Payload.dll";
    ProcessManager procManager;
    DWORD pid = procManager.GetProcessIdByName(targetProcess);

    if (pid == 0)
    {
        std::cerr << "Target process not found. " << std::endl;
        return 1;
    }
    std::cout << "Found target process PID: " << pid << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "Failed to open process handle. Do you have Administrator rights?" << std::endl;
        return 1;
    }
    std::cout <<"Successfully opened process handle." << std::endl;
    Injector injector;
    std::cout << "Attempting Standard Injection (CreateRemoteThread)..." << std::endl;
    bool success = injector.InjectStandard(hProcess, dllPath);
    // bool success = injector.InjectAPC(pid, hProcess, dllPath);
    // bool success = injector.InjectHijack(pid, hProcess, dllPath);

    if (success)
    {
        std::cout << "[+] Injection successful! Payload executed." << std::endl;
    }
    else
    {
        std::cerr << "[-] Injection failed." << std::endl;
    }
    CloseHandle(hProcess);

    return 0;
}