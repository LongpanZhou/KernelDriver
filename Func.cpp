#include "Mem.cpp"

PVOID EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName)
{
    // Check if EProcess is empty
    if (!pEProcess ) return nullptr;

    // Check if target module name is empty
    print(INFO("Target Module Name: %ws"), ModuleName);
    if (!ModuleName || ModuleName[0] == '\0')
        return nullptr;

    // Get KProcess n CR3
    _KPROCESS *pKProcess = (_KPROCESS *) CONTAINING_RECORD(pEProcess, _EPROCESS, Pcb);
    cr3 CR3 = {pKProcess->DirectoryTableBase};

    // Get PEB (Process Environment Block)
    _PEB *pPeb = pEProcess->Peb;
    if (!pPeb) return nullptr;


    // Read LDR (Loader Dynamic Resources)
    _PEB_LDR_DATA *pLdr = ReadVirtualMemory<_PEB_LDR_DATA*>(&pPeb->Ldr, CR3);
    if (!pLdr) return nullptr;

    // Init variables for loop
    wchar_t pBuffer[256];
    _LDR_DATA_TABLE_ENTRY ldrEntry;
    _LIST_ENTRY moduleList = ReadVirtualMemory<_LIST_ENTRY>(&pLdr->InLoadOrderModuleList, CR3);
    UNICODE_STRING moduleName;

    _LIST_ENTRY* pHead = moduleList.Flink;
    _LIST_ENTRY* pCurrent = moduleList.Flink;

    // Loop through all modules
    do
    {
        // Get LDR Entry n increment pCurrent
        if (!ReadVirtualMemory(pCurrent, CR3, &ldrEntry, sizeof(_LDR_DATA_TABLE_ENTRY)))
            break;

        // Load module name n increment pCurrent
        moduleName = ldrEntry.BaseDllName;
        pCurrent = ldrEntry.InLoadOrderLinks.Flink;

        // Check if Dll is valid
        if (!(ldrEntry.DllBase && moduleName.Length && moduleName.Buffer))
            continue;

        // Read memory into buffer
        if (!ReadVirtualMemory(moduleName.Buffer, CR3, &pBuffer, sizeof(pBuffer)))
            continue;

        // Print info
        print(INFO("Module Name: %ws"), pBuffer);

        // Substring cmp
        if (!wcscmp(pBuffer, ModuleName))
            return GetPhysicalAddress(ldrEntry.DllBase, CR3);
    } while (pCurrent != pHead);

    return nullptr;
}

_EPROCESS *EnumerateProcess(const wchar_t *ProcessName)
{
    // Check if target process name is empty
    print(INFO("Target Process Name: %ws"), ProcessName);
    if (!ProcessName || ProcessName[0] == '\0')
        return nullptr;

    // Get system default EProcess n ListEntry
    _EPROCESS *Process = (_EPROCESS *) win::PsInitialSystemProcess;
    _LIST_ENTRY *pHead = &(Process->ActiveProcessLinks);
    _LIST_ENTRY *pCurrent = pHead->Flink;

    // Loop through all process
    while (pCurrent != pHead)
    {
        // Get EProcess from ListEntry
        _EPROCESS *pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
        pCurrent = pCurrent->Flink;

        // Check if EProcess has ImageFilePointer n FilePath
        if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length)
            continue;

        // Print info
        print(INFO("Process Name: %s, PID: %d, File Path: %ws"),
              pProcess->ImageFileName, pProcess->UniqueProcessId,
              pProcess->ImageFilePointer->FileName.Buffer);

        // Str cmp
        if (wcsstr(pProcess->ImageFilePointer->FileName.Buffer, ProcessName))
            return pProcess;
    }

    return nullptr;
}
