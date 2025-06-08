#include "Func.cpp"

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
    // _EPROCESS* pEProcess = EnumerateEProcess(L"notepad.exe");
    // void* pModule = EnumerateModuleBaseAddress(pEProcess, L"ntdll.dll");
    // print(INFO("Module Address: %p"), pModule);

    // _EPROCESS* pEProcess = EnumerateEProcess(L"System", 4);
    // void* pModule = EnumerateModuleBaseAddress(pEProcess, L"ntdll.dll");
    // print(INFO("Module Address: %p"), pModule);

    void* tmp = EnumerateKProcess(L"ntoskrnl.exe");
    auto t = ReadVirtualMemory<void*>(tmp, 0x1ad000);
    print(INFO("value: %p"), t);
    return ntstatus::success;
}