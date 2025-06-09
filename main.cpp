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

    // void *tmp = EnumerateKProcess(L"ntoskrnl.exe");
    // auto t = ReadVirtualMemory<void *>(tmp, 0x1ad000);
    // print(INFO("value: %p"), t);

    char test[] = "48 89 5C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 81 EC";
    //SectionScan(L"",L"ntoskrnl.exe",".text\0\0\0",test);
    void* tmp = SectionScan(L"notepad.exe",L"ntdll.dll",".text\0\0\0",test);
    print(INFO("address: %p"),tmp);
    return ntstatus::success;
}
