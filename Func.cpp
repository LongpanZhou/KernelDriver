#include "Mem.cpp"

PVOID EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName)
{
    // Check if EProcess is empty
    if (!pEProcess) return nullptr;
    print(INFO("EProcess Address: %p"), pEProcess);
    print(INFO("Target Module Name: %ws"), ModuleName);

    // Get KProcess n CR3
    _KPROCESS *pKProcess = (_KPROCESS *) CONTAINING_RECORD(pEProcess, _EPROCESS, Pcb);
    cr3 CR3 = {pKProcess->DirectoryTableBase};
    print(INFO("KProcess Address: %p"), pKProcess);
    print(INFO("KProcess CR3: %p"), (ULONGLONG) CR3);

    // Get PEB (Process Environment Block)
    _PEB *pPeb = pEProcess->Peb;
    if (!pPeb) return nullptr;

    // Read LDR (Loader Dynamic Resources)
    _PEB_LDR_DATA *pLdr = ReadVirtualMemory<_PEB_LDR_DATA *>(&pPeb->Ldr, CR3);
    if (!pLdr) return nullptr;

    // Init variables for loop
    wchar_t pBuffer[256];
    _LDR_DATA_TABLE_ENTRY entry;
    _LIST_ENTRY moduleList = ReadVirtualMemory<_LIST_ENTRY>(&pLdr->InLoadOrderModuleList, CR3);
    UNICODE_STRING moduleName;

    _LIST_ENTRY *pHead = moduleList.Flink;
    _LIST_ENTRY *pCurrent = moduleList.Flink;

    // Loop through all modules
    do
    {
        // Get LDR Entry
        if (!ReadVirtualMemory(pCurrent, CR3, &entry, sizeof(_LDR_DATA_TABLE_ENTRY)))
            break;

        // Get module name n increment pCurrent
        moduleName = entry.BaseDllName;
        pCurrent = entry.InLoadOrderLinks.Flink;

        // Check if Dll is valid
        if (!(entry.DllBase && moduleName.Length && moduleName.Buffer))
            continue;

        // Read memory into buffer
        if (!ReadVirtualMemory(moduleName.Buffer, CR3, &pBuffer, sizeof(pBuffer)))
            continue;

        // Print info
        print(INFO("Module Name: %ws"), pBuffer);

        // Str cmp
        if (!wcscmp(pBuffer, ModuleName))
            return entry.DllBase;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ModuleName);
    return nullptr;
}

PVOID EnumerateKProcess(const wchar_t *ProcessName, const uint64_t PID = -1)
{
    // Parameters
    print(INFO("Target KProcess Name: %ws"), ProcessName);
    print(INFO("Target PID: %p"), PID);

    // Init variables for loop
    _LIST_ENTRY *pHead = (_LIST_ENTRY *) win::PsLoadedModuleList;
    _LIST_ENTRY *pCurrent = pHead;

    _KLDR_DATA_TABLE_ENTRY *entry;
    _UNICODE_STRING moduleName;

    // Loop through all kernel modules
    do
    {
        // Get KLDR entry n get module name n increment pCurrent
        entry = CONTAINING_RECORD(pCurrent, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        moduleName = entry->BaseDllName;
        pCurrent = pCurrent->Flink;

        // Check if module is valid
        if (!(entry->DllBase && moduleName.Length && moduleName.Buffer))
            continue;

        // Print info
        print(INFO("Module Name: %ws"), moduleName.Buffer);

        // Str cmp
        if (!wcscmp(moduleName.Buffer, ProcessName))
            return entry->DllBase;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}

_EPROCESS *EnumerateEProcess(const wchar_t *ProcessName, const uint64_t PID = -1)
{
    // Parameters
    print(INFO("Target EProcess Name: %ws"), ProcessName);
    print(INFO("Target PID: %p"), PID);
    size_t targetLen = wcslen(ProcessName);

    // Get system default EProcess n ListEntry
    _EPROCESS *Process = (_EPROCESS *) win::PsInitialSystemProcess;
    _LIST_ENTRY *pHead = &(Process->ActiveProcessLinks);
    _LIST_ENTRY *pCurrent = pHead;

    // Loop through all process
    do
    {
        // Get EProcess from ListEntry
        _EPROCESS *pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
        pCurrent = pCurrent->Flink;

        // PID cmp
        print(INFO("Process Name: %s, PID: %d"), pProcess->ImageFileName, pProcess->UniqueProcessId);
        if (pProcess->UniqueProcessId == (void *) PID)
            return pProcess;

        // Check if EProcess has ImageFilePointer n FilePath
        if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length)
            continue;

        // Print info
        print(INFO("File Path: %ws"),
              pProcess->ImageFilePointer->FileName.Buffer);

        // Sub str cmp
        size_t processLen = pProcess->ImageFilePointer->FileName.Length / sizeof(wchar_t);
        if (!wcscmp(pProcess->ImageFilePointer->FileName.Buffer + processLen - targetLen, ProcessName))
            return pProcess;
    } while (pCurrent != pHead);

    // Not Found
    print(ERROR("%ws NOT FOUND!"), ProcessName);
    return nullptr;
}

PVOID SignatureScan(const void *StartAddress, const void *EndAddress, const char *Signature)
{
    return nullptr;
}

PVOID TextSectionScan(const wchar_t *ProcessName, const wchar_t *ModuleName, const char *Signature)
{
    // Print info
    print(INFO("ProcessName: %ws"), ProcessName);
    print(INFO("ModuleName: %ws"), ModuleName);
    print(INFO("Signature: %s"), Signature);

    // Initialize variables (empty = Kernel, else = User)
    address BaseAddress = ProcessName[0] == L'\0'
                              ? EnumerateKProcess(ModuleName)
                              : EnumerateModuleBaseAddress(EnumerateEProcess(ProcessName), ModuleName);
    if (!BaseAddress) return nullptr;

    // Get .text section
    _IMAGE_DOS_HEADER *dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    _IMAGE_NT_HEADERS64 *ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    _IMAGE_FILE_HEADER *fileHeader = &ntHeader->FileHeader;
    _IMAGE_OPTIONAL_HEADER64 *optionalHeader = &ntHeader->OptionalHeader;
    _IMAGE_SECTION_HEADER *sectionHeader = (_IMAGE_SECTION_HEADER *) ((uint64_t)optionalHeader + sizeof(_IMAGE_OPTIONAL_HEADER64));
    void *textSectionStart{}, *textSectionEnd{};

    // loop
    for (int i = 0; i < fileHeader->NumberOfSections; i++)
    {
        if (!memcmp(sectionHeader[i].Name, ".text\0\0\0", 8))
        {
            textSectionStart = BaseAddress + sectionHeader[i].VirtualAddress;
            textSectionEnd = BaseAddress + sectionHeader->VirtualAddress + sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // Signature Scan
    return SignatureScan(textSectionStart, textSectionEnd, Signature);
}