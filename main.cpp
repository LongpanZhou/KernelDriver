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

    void* pEProcess = EnumerateEProcess(L"explorer.exe");
    void* pKProcess = CONTAINING_RECORD(pEProcess, _EPROCESS, Pcb);

    _KAPC_STATE KapcState{};
    win::KeStackAttachProcess(pKProcess,(uint64_t*)&KapcState);

    char test[] = "48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? EB ? B8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? EB ? B8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0";
    SectionScan(L"",L"win32k.sys",".text\0\0\0",test);
    win::KeUnstackDetachProcess((uint64_t*)&KapcState);

    return ntstatus::success;
}
