#define WIN32_MEAN_AND_LEAN
#include <Windows.h>
#include <iostream>
#include "include/MinHook.h"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

void MainThread()
{
	MessageBoxA(NULL, "Peterhack", "Main Frame", MB_OK);
}

EXTERN_DLL_EXPORT void DllEntry()
{
	HANDLE hThread = CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(MainThread), nullptr, NULL, NULL);
	if (hThread)
		CloseHandle(hThread);
}

