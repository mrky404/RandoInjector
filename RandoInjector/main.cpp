#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <random>

// Define the DLL name
#define DLL_NAME "Osiris.dll"
#define NUM_BYTES 5

DWORD GetProcessID(const char* processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create snapshot" << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) {
        std::cerr << "[-] Failed to get first process" << std::endl;
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(pe.szExeFile, processName) == 0) {
            DWORD pid = pe.th32ProcessID;
            CloseHandle(hSnapshot);
            return pid;
        }
    } while (Process32Next(hSnapshot, &pe));

    std::cerr << "[-] Failed to find process" << std::endl;
    CloseHandle(hSnapshot);
    return 0;
}

int main()
{
    char myDLL[MAX_PATH];
    GetFullPathName(DLL_NAME, MAX_PATH, myDLL, NULL);

    DWORD dwProcessID = GetProcessID("csgo.exe");
    if (dwProcessID == 0)
        return 1;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hProcess == NULL)
        return 1;

    LPVOID ntOpenFile = GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenFile");

    if (ntOpenFile) {
        char originalBytes[NUM_BYTES];
        memcpy(originalBytes, ntOpenFile, NUM_BYTES);
        WriteProcessMemory(hProcess, ntOpenFile, originalBytes, NUM_BYTES, NULL);
    }

    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, allocatedMem, myDLL, sizeof(myDLL), NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, NULL);

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Free the allocated memory
    VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);

    // Close the handles
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}