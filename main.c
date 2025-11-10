#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD GetPIDByName(char* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                DWORD pid = pe32.th32ProcessID;
                CloseHandle(hSnapshot);
                return pid;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}   


int main(){
    char* ProcessName = "Notepad.exe";
    char* DllName = "MessageBoxDLL.dll";
    char FullDLLPath[MAX_PATH];

    // printf("Name of the Process : ");
    // scanf("%s", &ProcessName);
    // printf("Name of the DLL : ");
    // scanf("%s", &DllName);


    printf("[+]   Starting Injection\n");

    DWORD pid = GetPIDByName(ProcessName);
    if(!pid) {
        printf("[-]   Faild to find process\n");
        return 1;
    }
    else {
        printf("[+]   Find Process : %d\n", pid);
    }
    HANDLE mainHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(mainHandle == NULL) {
        printf("[-]   Can't open Process\n");
        return 1;
    }
    else {
        printf("[+]   Open Process\n");
    }


    DWORD dwFullPathResult = GetFullPathNameA(DllName, MAX_PATH, FullDLLPath, NULL);
    if(dwFullPathResult == 0) {
        printf("[-]   GetDllPath fail\n");
    }

    LPVOID allocMem = VirtualAllocEx(mainHandle, NULL, lstrlenA(FullDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(allocMem == NULL) {
        printf("[-]   Fail to AllocMem\n");
        CloseHandle(mainHandle);
        return 1;
    }
    else {
        printf("[+]   AllocMem Succes\n");
    }


    BOOL WriteMem = WriteProcessMemory(mainHandle, allocMem, FullDLLPath, lstrlenA(FullDLLPath) + 1, NULL);
    if(WriteMem == 0) {
        printf("[-]   WriteMemory Fail\n");
        VirtualFree(allocMem, lstrlenA(FullDLLPath) + 1, MEM_RELEASE);
        CloseHandle(mainHandle);
        return 1;
    }
    else {
        printf("[+]   WriteMemory Succes\n");
    }



    HMODULE hModule = GetModuleHandleA("kernel32.dll");
    if(hModule == NULL) {
        printf("[-]   GetModuleHandle fail\n");
        VirtualFree(allocMem, lstrlenA(FullDLLPath) + 1, MEM_RELEASE);
        CloseHandle(mainHandle);
        return 1;
    }
    else {
        printf("[+]   GetModuleHandle Succes\n");
    }
    FARPROC LoadLibAddr = GetProcAddress(hModule, "LoadLibraryA");
    if(LoadLibAddr == NULL) {
        printf("[-]   Can't find LoadLib addr\n");
        VirtualFree(allocMem, lstrlenA(FullDLLPath) + 1, MEM_RELEASE);
        CloseHandle(mainHandle);
        return 1;
    }
    else {
        printf("[+]   Find LoadLib addr\n");

    }



    HANDLE hSeconde = CreateRemoteThread(mainHandle, NULL, 0, (LPTHREAD_START_ROUTINE) LoadLibAddr, allocMem, 0, NULL);
    if(hSeconde == NULL) {
        printf("[-]   CreateRemoteThread Fail\n");
        VirtualFree(allocMem, lstrlenA(FullDLLPath) + 1, MEM_RELEASE);
        CloseHandle(mainHandle);
        return 1;
    }
    else {
        printf("[+]   CreateRemoteThread Succes\n");
    }
    
    printf("Finish Injecting");
    CloseHandle(mainHandle);
    return 0;
}