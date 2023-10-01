#include <iostream>  // Include the I/O stream library
#include <Windows.h>  // Include the Windows API library
#include <TlHelp32.h>  // Include the Tool Help library
#include <random>  // Include the random library

#define DLL_NAME "MY_DLL_NAME.dll"  // Define the DLL name
#define NUM_BYTES 5  // Define the number of bytes

// Function to get the process ID given a process name
DWORD GetProcessID(const char* processName)
{
    // Create a snapshot of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create snapshot" << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process from the snapshot
    if (!Process32First(hSnapshot, &pe)) {
        std::cerr << "[-] Failed to get first process" << std::endl;
        CloseHandle(hSnapshot);
        return 0;
    }

    // Loop through all processes in the snapshot
    do {
        // If the process name matches, return its ID
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
    GetFullPathName(DLL_NAME, MAX_PATH, myDLL, NULL);  // Get the full path of the DLL

    DWORD dwProcessID = GetProcessID("csgo.exe");  // Get the process ID of "csgo.exe"
    if (dwProcessID == 0)
        return 1;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);  // Open the process with all access rights
    if (hProcess == NULL)
        return 1;

    LPVOID ntOpenFile = GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenFile");  // Get the address of the NtOpenFile function

    if (ntOpenFile) {
        char originalBytes[NUM_BYTES];
        memcpy(originalBytes, ntOpenFile, NUM_BYTES);  // Copy the original bytes of NtOpenFile
        WriteProcessMemory(hProcess, ntOpenFile, originalBytes, NUM_BYTES, NULL);  // Write the original bytes back to NtOpenFile in the target process
    }

    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);  // Allocate memory in the target process
    WriteProcessMemory(hProcess, allocatedMem, myDLL, sizeof(myDLL), NULL);  // Write the DLL path to the allocated memory

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, NULL);  // Create a remote thread that loads our DLL

    WaitForSingleObject(hThread, INFINITE);  // Wait for the remote thread to finish

    VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);  // Free the allocated memory

    CloseHandle(hThread);  // Close the thread handle
    CloseHandle(hProcess);  // Close the process handle

    return 0; 
}
