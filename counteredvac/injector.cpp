#include "injector.hpp"

BOOLEAN CInjector::LoadFileIntoMemory(const wchar_t* FilePath, PVOID& FileBytes, SIZE_T& FileSize)
{
    if (GetFileAttributes(FilePath) == INVALID_FILE_ATTRIBUTES)
        return false;

    std::ifstream File(FilePath, std::ios::binary | std::ios::ate);
    if (File.fail())
    {
        File.close();
        return false;
    }

    auto tFileSize = File.tellg();
    if (tFileSize < 0x1000) // 4kb
    {
        File.close();
        return false;
    }

    void* FilePointer = malloc(tFileSize);
    if (!FilePointer)
    {
        File.close();
        return false;
    }

    File.seekg(0, std::ios::beg);
    File.read((char*)FilePointer, tFileSize);
    File.close();

    FileBytes = FilePointer;
    FileSize = tFileSize;
    return true;
}
BOOLEAN CInjector::FixSections(const PVOID remoteMemory, const PVOID moduleData)
{
    IMAGE_NT_HEADERS* pNtHeaders = GetImageNtHeader(moduleData);
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData) {
            void* dest = static_cast<BYTE*>(remoteMemory) + pSectionHeader[i].VirtualAddress;
            void* src = static_cast<BYTE*>(moduleData) + pSectionHeader[i].PointerToRawData;
            if (!WriteMemory(dest, src, pSectionHeader[i].SizeOfRawData)) {
                return false;
            }
        }
    }

    return true;
}
BOOLEAN CInjector::FixReallocations(const PVOID remoteMemory, const PVOID moduleData)
{
    IMAGE_NT_HEADERS* pNtHeaders = GetImageNtHeader(moduleData);

    bool is_64bit = pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        SIZE_T delta = reinterpret_cast<SIZE_T>(remoteMemory) - pNtHeaders->OptionalHeader.ImageBase;
        if (delta != 0) {
            void* reloc_address = static_cast<BYTE*>(remoteMemory) +
                pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            IMAGE_BASE_RELOCATION reloc_block;

            while (ReadMemory(reloc_address, &reloc_block, sizeof(IMAGE_BASE_RELOCATION)) && reloc_block.VirtualAddress) {
                DWORD num_entries = (reloc_block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                std::vector<WORD> reloc_entries(num_entries);
                void* entries_address = static_cast<BYTE*>(reloc_address) + sizeof(IMAGE_BASE_RELOCATION);

                if (!ReadMemory(entries_address, reloc_entries.data(), num_entries * sizeof(WORD))) {
                    return false;
                }

                for (DWORD i = 0; i < num_entries; i++) {
                    WORD reloc_type = reloc_entries[i] >> 12;
                    DWORD offset = reloc_entries[i] & 0xFFF;

                    if (reloc_type == IMAGE_REL_BASED_HIGHLOW && !is_64bit) {
                        DWORD* patch_address = reinterpret_cast<DWORD*>(
                            static_cast<BYTE*>(remoteMemory) + reloc_block.VirtualAddress + offset);
                        DWORD current_value;
                        if (!ReadMemory(patch_address, &current_value, sizeof(DWORD)) ||
                            !WriteMemory( patch_address, &(current_value += static_cast<DWORD>(delta)), sizeof(DWORD))) {
                            return false;
                        }
                    }
                    else if (reloc_type == IMAGE_REL_BASED_DIR64 && is_64bit) {
                        ULONGLONG* patch_address = reinterpret_cast<ULONGLONG*>(
                            static_cast<BYTE*>(remoteMemory) + reloc_block.VirtualAddress + offset);
                        ULONGLONG current_value;
                        if (!ReadMemory(patch_address, &current_value, sizeof(ULONGLONG)) ||
                            !WriteMemory(patch_address, &(current_value += delta), sizeof(ULONGLONG))) {
                            return false;
                        }
                    }
                }

                reloc_address = static_cast<BYTE*>(reloc_address) + reloc_block.SizeOfBlock;
            }
        }
    }

    return true;
}
BOOLEAN CInjector::FixImportAddressTable(const PVOID remoteMemory, const PVOID moduleData)
{
    IMAGE_NT_HEADERS* pNtHeaders = GetImageNtHeader(moduleData);

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            static_cast<BYTE*>(remoteMemory) +
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        IMAGE_IMPORT_DESCRIPTOR import_desc = {};
        if (!ReadMemory(pImportDesc, &import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return false;
        }

        while (import_desc.Name) {
            char dll_name[256] = { 0 };
            void* name_address = static_cast<BYTE*>(remoteMemory) + import_desc.Name;
            if (!ReadMemory(name_address, dll_name, sizeof(dll_name) - 1)) {
                return false;
            }

            HMODULE hModule = LoadLibraryA(dll_name);
            if (!hModule) {
                return false;
            }

            IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                static_cast<BYTE*>(remoteMemory) + import_desc.FirstThunk);
            IMAGE_THUNK_DATA* pOrigThunk = import_desc.OriginalFirstThunk ?
                reinterpret_cast<IMAGE_THUNK_DATA*>(
                    static_cast<BYTE*>(remoteMemory) + import_desc.OriginalFirstThunk) :
                pThunk;

            IMAGE_THUNK_DATA thunk_data = {};
            if (!ReadMemory(pOrigThunk, &thunk_data, sizeof(IMAGE_THUNK_DATA))) {
                FreeLibrary(hModule);
                return false;
            }

            while (thunk_data.u1.AddressOfData) {
                if (thunk_data.u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    SIZE_T func_address = reinterpret_cast<SIZE_T>(
                        GetProcAddress(hModule, reinterpret_cast<LPCSTR>(thunk_data.u1.Ordinal & 0xFFFF)));
                    if (!func_address) {
                        FreeLibrary(hModule);
                        return false;
                    }
                    if (!WriteMemory(pThunk, &func_address, sizeof(SIZE_T))) {
                        FreeLibrary(hModule);
                        return false;
                    }
                }
                else {
                    IMAGE_IMPORT_BY_NAME import_by_name = {};
                    void* import_by_name_address = static_cast<BYTE*>(remoteMemory) + thunk_data.u1.AddressOfData;
                    if (!ReadMemory(import_by_name_address, &import_by_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
                        FreeLibrary(hModule);
                        return false;
                    }

                    char func_name[256] = { 0 };
                    if (!ReadMemory(static_cast<BYTE*>(import_by_name_address) + offsetof(IMAGE_IMPORT_BY_NAME, Name), func_name, sizeof(func_name) - 1)) {
                        FreeLibrary(hModule);
                        return false;
                    }

                    SIZE_T func_address = reinterpret_cast<SIZE_T>(GetProcAddress(hModule, func_name));
                    if (!func_address) {
                        FreeLibrary(hModule);
                        return false;
                    }
                    if (!WriteMemory(pThunk, &func_address, sizeof(SIZE_T))) {
                        FreeLibrary(hModule);
                        return false;
                    }
                }

                pThunk++;
                pOrigThunk++;
                if (!ReadMemory(pOrigThunk, &thunk_data, sizeof(IMAGE_THUNK_DATA))) {
                    break;
                }
            }
            FreeLibrary(hModule);

            pImportDesc++;
            if (!ReadMemory(pImportDesc, &import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
                break;
            }
        }
    }

    return true;
}
PVOID CInjector::GetModuleExportFunction(const PVOID remoteMemory, const PVOID moduleData, const char* ExportName)
{
    IMAGE_NT_HEADERS* pNtHeaders = GetImageNtHeader(moduleData);

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        IMAGE_EXPORT_DIRECTORY* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            static_cast<BYTE*>(remoteMemory) +
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        IMAGE_EXPORT_DIRECTORY export_dir = {};
        if (!ReadMemory(pExportDir, &export_dir, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            return nullptr;
        }

        if (export_dir.NumberOfFunctions > 0) {
            DWORD* pAddressOfFunctions = reinterpret_cast<DWORD*>(
                static_cast<BYTE*>(remoteMemory) + export_dir.AddressOfFunctions);
            DWORD* pAddressOfNames = reinterpret_cast<DWORD*>(
                static_cast<BYTE*>(remoteMemory) + export_dir.AddressOfNames);
            WORD* pAddressOfNameOrdinals = reinterpret_cast<WORD*>(
                static_cast<BYTE*>(remoteMemory) + export_dir.AddressOfNameOrdinals);

            std::vector<DWORD> func_rvas(export_dir.NumberOfFunctions);
            if (!ReadMemory(pAddressOfFunctions, func_rvas.data(),
                export_dir.NumberOfFunctions * sizeof(DWORD))) {
                return nullptr;
            }

            std::vector<DWORD> name_rvas(export_dir.NumberOfNames);
            if (!ReadMemory(pAddressOfNames, name_rvas.data(),
                export_dir.NumberOfNames * sizeof(DWORD))) {
                return nullptr;
            }

            std::vector<WORD> ordinals(export_dir.NumberOfNames);
            if (!ReadMemory(pAddressOfNameOrdinals, ordinals.data(),
                export_dir.NumberOfNames * sizeof(WORD))) {
                return nullptr;
            }

            for (DWORD i = 0; i < export_dir.NumberOfNames; i++) {
                char func_name[256] = { 0 };
                void* name_address = static_cast<BYTE*>(remoteMemory) + name_rvas[i];
                if (!ReadMemory(name_address, func_name, sizeof(func_name) - 1)) {
                    return nullptr;
                }

                WORD ordinal = export_dir.Base + ordinals[i];
                DWORD func_rva = func_rvas[ordinals[i]];
                void* func_address = static_cast<BYTE*>(remoteMemory) + func_rva;

                if (strcmp(func_name, ExportName) == 0) {
                    return func_address;
                }
            }
        }
    }
}
BOOLEAN CInjector::CleanSections(const PVOID remoteMemory, const PVOID moduleData) {
    const IMAGE_NT_HEADERS* NtHeaders = GetImageNtHeader(moduleData);
    const IMAGE_SECTION_HEADER* const sectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

    static const char* const uselessSections[] = {
        ".reloc",  // realloc
        ".rsrc",   // resources
        ".edata",  // exports
        ".idata",  // imports
        ".pdata"   // exception handle data
    };
    constexpr size_t numUselessSections = sizeof(uselessSections) / sizeof(uselessSections[0]);

    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i) {
        char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
        strncpy_s(sectionName, reinterpret_cast<const char*>(sectionHeader[i].Name), IMAGE_SIZEOF_SHORT_NAME);

        bool isUseless = false;
        for (size_t j = 0; j < numUselessSections; ++j) {
            if (strcmp(sectionName, uselessSections[j]) == 0) {
                isUseless = true;
                break;
            }
        }

        if (isUseless && sectionHeader[i].SizeOfRawData > 0) {
            void* const sectionAddress = static_cast<BYTE*>(remoteMemory) + sectionHeader[i].VirtualAddress;
            std::vector<char> zeroBuffer(sectionHeader[i].SizeOfRawData, 0);
            if (!WriteMemory(sectionAddress, zeroBuffer.data(), sectionHeader[i].SizeOfRawData)) {
                return false;
            }
        }
    }
    return true;
}
BOOLEAN CInjector::CleanPeHeader(const PVOID remoteMemory, const PVOID moduleData)
{
    const IMAGE_NT_HEADERS* pNtHeaders = GetImageNtHeader(moduleData);
    char CleanBuffer = 0;
    if (!WriteMemory(remoteMemory, &CleanBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders))
    {
        return false;
    }
    else
    {
        return true;
    }
}

BOOLEAN CInjector::MapDll(void* module_data, size_t module_size, BOOLEAN UseRemoteThread) {
    if (!module_data || !Attached) return false;

    IMAGE_DOS_HEADER* pDosHeader;
    IMAGE_NT_HEADERS* pNtHeaders;
    SIZE_T ImageSize = 0;

    pDosHeader = GetImageDosHeader(module_data);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    this->Log("pDosHeader -> %p", pDosHeader);

    pNtHeaders = GetImageNtHeader(module_data);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE || pNtHeaders->OptionalHeader.SizeOfImage == 0) return false;

    this->Log("pNtHeaders -> %p", pNtHeaders);

    ImageSize = pNtHeaders->OptionalHeader.SizeOfImage;

    this->Log("image size (bytes) -> %d", ImageSize);

    PVOID remoteMemory = AllocateMemory(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) return false;

    this->Log("allocate memory -> %p", remoteMemory);

    if (!WriteMemory(remoteMemory, module_data, module_size)) {
        this->Log("failed to write dll into remote memory");
        FreeMemory(remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    this->Log("wrote dll into memory");

    if (!FixSections(remoteMemory, module_data))
    {
        this->Log("failed to fix sections");
        FreeMemory(remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    this->Log("fixed/mapped dll sections");

    if (!FixReallocations(remoteMemory, module_data))
    {
        this->Log("failed to fix reallocations");
        FreeMemory(remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    this->Log("fix dll reallocations");

    if (!FixImportAddressTable(remoteMemory, module_data))
    {
        this->Log("failed to fix import address table");
        FreeMemory(remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    this->Log("fixed dll IAT(import address table)");

    // reslove here before we clean the export section

    void* dllExportEntry = GetModuleExportFunction(remoteMemory, module_data, "DllEntry");
    if (!dllExportEntry)
    {
        this->Log("failed to reslove DllEntry ( is it exported? )");
        FreeMemory(remoteMemory, 0, MEM_RELEASE);
        return false;
    }
    
    this->Log("resloved DllEntry -> %p", dllExportEntry);

    if (!CleanSections(remoteMemory, module_data))
    {
        this->Log("failed to clear useless sections");
    }
    else
    {
        this->Log("cleaned unneeded sections");
    }

    if (!CleanPeHeader(remoteMemory, module_data))
    {
        this->Log("failed to clean pe headers");
    }
    else
    {
        this->Log("cleaned pe headers");
    }

    this->Log("calling dll entry");

    if (UseRemoteThread)
    {
        this->Log("using CreateRemoteThread");
    }
    else
    {
        this->Log("using thread");
    }

    if (dllExportEntry) {
        if (!UseRemoteThread) {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                FreeMemory(remoteMemory, 0, MEM_RELEASE);
                return false;
            }

            THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
            const DWORD processId = GetProcessId(ProcessHandle);
            HANDLE threadHandle = nullptr;

            if (Thread32First(snapshot, &threadEntry)) {
                do {
                    if (threadEntry.th32OwnerProcessID == processId) {
                        threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
                        if (threadHandle) {
                            break;
                        }
                    }
                } while (Thread32Next(snapshot, &threadEntry));
            }

            CloseHandle(snapshot);

            if (!threadHandle) {
                this->Log("failed to call dll entry");
                FreeMemory(remoteMemory, 0, MEM_RELEASE);
                return false;
            }

            if (SuspendThread(threadHandle) == (DWORD)-1) {
                this->Log("failed to call dll entry");
                CloseHandle(threadHandle);
                FreeMemory(remoteMemory, 0, MEM_RELEASE);
                return false;
            }

            CONTEXT threadContext = { 0 };
            threadContext.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(threadHandle, &threadContext)) {
                this->Log("failed to call dll entry");
                ResumeThread(threadHandle);
                CloseHandle(threadHandle);
                FreeMemory(remoteMemory, 0, MEM_RELEASE);
                return false;
            }

            threadContext.Rip = reinterpret_cast<DWORD64>(dllExportEntry);

            if (!SetThreadContext(threadHandle, &threadContext))
            {
                this->Log("failed to call dll entry");
                ResumeThread(threadHandle);
                CloseHandle(threadHandle);
                FreeMemory(remoteMemory, 0, MEM_RELEASE);
                return false;
            }

            ResumeThread(threadHandle);

            CloseHandle(threadHandle);
        }
        else
        {
             HANDLE thread = CreateRemoteThread(ProcessHandle, NULL, 0,
                 reinterpret_cast<LPTHREAD_START_ROUTINE>(dllExportEntry),
                 nullptr, 0, nullptr);
            
             if (!thread)
             {
                 this->Log("failed to call dll entry");
                 FreeMemory(remoteMemory, 0, MEM_RELEASE);
                 return false;
             }
             else
             {
                 CloseHandle(thread);
             }
        }
 

        this->Log("called dll entry");
        this->Log("hi, jack who are you ??");
    }

    return true;
}