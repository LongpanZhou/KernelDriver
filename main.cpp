#include "Func.cpp"

// Declarations
PVOID EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName);
_EPROCESS *EnumerateProcess(const wchar_t *ProcessName);

ntstatus DriverExit(PDRIVER_OBJECT)
{
    // Nothing here yet
    return ntstatus::success;
}

extern "C"
ntstatus DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
    // Initialization
    DriverObject->DriverUnload = DriverExit;

    // Main
    _EPROCESS* EProcess = EnumerateProcess(L"notepad.exe");
    print(INFO("EProcess Address: %p"), EProcess);

    void* pModule = EnumerateModuleBaseAddress(EProcess, L"ntdll.dll");
    print(INFO("Module Address: %p"), pModule);
    return ntstatus::success;
}