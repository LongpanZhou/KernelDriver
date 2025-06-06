#include "Func.cpp"

// Declarations
PVOID EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName);
_EPROCESS *EnumerateProcess(const wchar_t *ProcessName);

ntstatus DriverExit(PDRIVER_OBJECT)
{
    ReadPhysical<address>(nullptr, 4); //Type 4 = Unmap
    return ntstatus::success;
}

extern "C"
ntstatus DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
    // Initialization
    DriverObject->DriverUnload = DriverExit;

    // Main
    _EPROCESS* pEProcess = EnumerateProcess(L"notepad.exe");
    void* pModule = EnumerateModuleBaseAddress(pEProcess, L"ntdll.dll");
    print(INFO("Module Address: %p"), pModule);

    return ntstatus::success;
}