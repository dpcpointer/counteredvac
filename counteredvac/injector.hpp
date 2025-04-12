#ifndef INJECTOR_HPP
#define INJECTOR_HPP

#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#include <iostream>
#include <memory>
#include <TlHelp32.h>
#include <varargs.h>
#include <fstream>
#include <vector>
#include "native.h"
#include "internal.hpp"

class CInjector
{
private:
    void Log(const char* const _Format, ...)
    {
        va_list args;
        va_start(args, _Format);
        printf("[injector] ");
        vprintf(_Format, args);
        printf("\n");
        va_end(args);
    }

    DWORD ProcessPid{ 0 };
    BOOLEAN Attached{ FALSE };
    HANDLE ProcessHandle{ NULL };

    DWORD GetProcessPID(const wchar_t* ProcessName)
    {
        if (!ProcessName)
            return 0;

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapShot == INVALID_HANDLE_VALUE)
            return 0;

        DWORD processPid{ 0 };
        while (Process32Next(snapShot, &entry))
        {
            if (!_wcsicmp(ProcessName, entry.szExeFile))
            {
                processPid = entry.th32ProcessID;
                break;
            }
        }
        if (snapShot != INVALID_HANDLE_VALUE)
            CloseHandle(snapShot);

        return processPid;
    }

    const bool ReadMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
        if (!Attached || !lpBaseAddress || !lpBuffer || !nSize || !ProcessHandle)
            return false;

        SIZE_T bytesRead;
        return ::ReadProcessMemory(ProcessHandle, lpBaseAddress, lpBuffer, nSize, &bytesRead) && bytesRead == nSize;
    }

    const bool WriteMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
        if (!Attached || !lpBaseAddress || !lpBuffer || !nSize || !ProcessHandle)
            return false;

        SIZE_T bytesWritten;
        return ::WriteProcessMemory(ProcessHandle, (LPVOID)lpBaseAddress, lpBuffer, nSize, &bytesWritten) && bytesWritten == nSize;
    }

    void* AllocateMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        if (!Attached || !dwSize || !flAllocationType || !flProtect || !ProcessHandle)
            return nullptr;

        return ::VirtualAllocEx(ProcessHandle, lpAddress, dwSize, flAllocationType, flProtect);
    }

    const bool ProtectMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        if (!Attached || !lpAddress || !dwSize || !flNewProtect || !lpflOldProtect || !ProcessHandle)
            return false;

        return ::VirtualProtectEx(ProcessHandle, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }

    const bool FreeMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
        if (!Attached || !lpAddress || !dwSize || !dwFreeType || !ProcessHandle)
            return false;

        return ::VirtualFreeEx(ProcessHandle, lpAddress, dwSize, dwFreeType);
    }

    BOOLEAN FixSections(const PVOID remoteMemory, const PVOID moduleData);
    BOOLEAN FixReallocations(const PVOID remoteMemory, const PVOID moduleData);
    BOOLEAN FixImportAddressTable(const PVOID remoteMemory, const PVOID moduleData);
    PVOID GetModuleExportFunction(const PVOID remoteMemory, const PVOID moduleData, const char* ExportName);
    BOOLEAN CleanSections(const PVOID remoteMemory, const PVOID moduleData);
    BOOLEAN CleanPeHeader(const PVOID remoteMemory, const PVOID moduleData);
public:	
    BOOLEAN Attach(const wchar_t* Process)
    {
        if (!Process)
            return FALSE;

        mempass::EnableSeDebugPrivilege();
     
        if (Attached)
            ProcessPid = 0;

        ProcessPid = GetProcessPID(Process);
        if (!ProcessPid)
        {
            Log("fail to process");
            return FALSE;
        }

        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessPid);
        if (!ProcessHandle) {
            Log("failed get handle");
            ProcessPid = 0;
            return FALSE;
        }

        Attached = TRUE;
        Log("attached to process", Process, ProcessPid);
        return TRUE;
    }
    BOOLEAN Detach() {
        if (!Attached)
            return TRUE;

        if (ProcessHandle) {
            CloseHandle(ProcessHandle);
            ProcessHandle = NULL;
        }

        ProcessPid = 0;
        Attached = FALSE;
        Log("detached from process");
        return TRUE;
    }

    BOOLEAN LoadFileIntoMemory(const wchar_t* FilePath, PVOID& FileBytes, SIZE_T& FileSize);
	BOOLEAN MapDll(void* module_data, size_t module_size, BOOLEAN UseRemoteThread);

    inline IMAGE_DOS_HEADER* GetImageDosHeader(const PVOID Image) {
        if (!Image)
            return nullptr;
        IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Image);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;
        return dosHeader;
    }
    inline IMAGE_NT_HEADERS* GetImageNtHeader(const PVOID Image) {
        IMAGE_DOS_HEADER* dosHeader = GetImageDosHeader(Image);
        if (!dosHeader || dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew > 0x10000)
            return nullptr;
        IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)Image + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;
        return ntHeaders;
    }
};

inline std::unique_ptr<CInjector> Injector;

#endif INJECTOR_HPP