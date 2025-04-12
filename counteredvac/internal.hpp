#ifndef INTERNAL_HPP
#define INTERNAL_HPp

#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#include <iostream>
#include <memory>
#include <TlHelp32.h>
#include <varargs.h>
#include <fstream>
#include <vector>
#include "native.h"

namespace mempass
{
    __forceinline void* GetPEB() {
#ifdef _M_X64 // 64-bit
        return (void*)__readgsqword(0x60); // PEB at GS:0x60
#elif _M_IX86 // 32-bit (including WOW64)
        return (void*)__readfsdword(0x30); // PEB at FS:0x30
#else
#error "Unsupported architecture"
#endif
    }
    // unsafe and crashes
    __forceinline void SetPEB(DWORD64 Data) {
#ifdef _M_X64 // 64-bit
        __writegsqword(0x60, Data); // PEB at GS:0x60
#elif _M_IX86 // 32-bit (including WOW64)
        __writegsqword(0x30, Data); // PEB at FS:0x30
#else
#error "Unsupported architecture"
#endif
    }

    __forceinline BOOL EnableSeDebugPrivilege() {
        HANDLE hToken;
        LUID luid;
        TOKEN_PRIVILEGES tp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return FALSE;
        }

        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return FALSE;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            CloseHandle(hToken);
            return FALSE;
        }

        CloseHandle(hToken);
        return TRUE;
    }
    __forceinline BOOL MitigationPolicy() {
        BOOL success = TRUE;

        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = { 0 };
        dynamicCodePolicy.ProhibitDynamicCode = 1;
        dynamicCodePolicy.AllowThreadOptOut = 0;
        dynamicCodePolicy.AllowRemoteDowngrade = 0;
        if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy))) {
            success = FALSE;
        }

        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handleCheckPolicy = { 0 };
        handleCheckPolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handleCheckPolicy.HandleExceptionsPermanentlyEnabled = 1;
        if (!SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &handleCheckPolicy, sizeof(handleCheckPolicy))) {
            success = FALSE;
        }

        PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = { 0 };
        imageLoadPolicy.NoRemoteImages = 1;
        imageLoadPolicy.NoLowMandatoryLabelImages = 1;
        imageLoadPolicy.PreferSystem32Images = 1;
        if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy))) {
            success = FALSE;
        }

        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };
        signaturePolicy.MicrosoftSignedOnly = 1;
        if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy))) {
            success = FALSE;
        }

        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPolicy = { 0 };
        extensionPolicy.DisableExtensionPoints = 1;
        if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extensionPolicy, sizeof(extensionPolicy))) {
            success = FALSE;
        }

        PROCESS_MITIGATION_FONT_DISABLE_POLICY fontPolicy = { 0 };
        fontPolicy.DisableNonSystemFonts = 1;
        if (!SetProcessMitigationPolicy(ProcessFontDisablePolicy, &fontPolicy, sizeof(fontPolicy))) {
            success = FALSE;
        }

        return success;
    }
    __forceinline BOOL SpoofPeb()
    {
        PPEB Peb = (PPEB)GetPEB();
        DWORD flOldProtect = 0;
        if (!::VirtualProtect(Peb, sizeof(PEB), PAGE_EXECUTE_READWRITE, &flOldProtect))
            return false;

        Peb->ImageBaseAddress = 0x0;
        Peb->BeingDebugged = true;

        return ::VirtualProtect(Peb, sizeof(PEB), flOldProtect, &flOldProtect);
    }
}

#endif