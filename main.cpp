#include "structs.h"
#include "utils.h"

using namespace arch;
using namespace intrin;

_EPROCESS *EnumerateProcess(const wchar_t *ProcessName);

ntstatus DriverExit(PDRIVER_OBJECT DriverObject)
{
    // Nothing here yet
    return ntstatus::success;
}

extern "C"
ntstatus DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    // Initialization
    DriverObject->DriverUnload = DriverExit;

    // Main
    print("%p", EnumerateProcess(L"notepad.exe"));
    return ntstatus::success;
}

template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback)
{
    cr3 CR3 = read_cr3();

    for (int PML4_IDX = 0; PML4_IDX < 256; PML4_IDX++)
    {
        pml4e PML4E = ((pml4e *) win::MmGetVirtualForPhysical({CR3.pml4_frame_number << 12}))[PML4_IDX];
        if (!PML4E.present) continue;

        for (int PDPT_IDX = 0; PDPT_IDX < 256; PDPT_IDX++)
        {
            pdpte PDPTE = ((pdpte *) win::MmGetVirtualForPhysical({PML4E.page_frame_number << 12}))[PDPT_IDX];
            if (!PDPTE.present) continue;

            for (int PD_IDX = 0; PD_IDX < 256; PD_IDX++)
            {
                pde PDE = ((pde *) win::MmGetVirtualForPhysical({PDPTE.page_frame_number << 12}))[PD_IDX];
                if (!PDE.present) continue;

                for (int PT_IDX = 0; PT_IDX < 256; PT_IDX++)
                {
                    pte PTE = ((pte *) win::MmGetVirtualForPhysical({PDPTE.page_frame_number << 12}))[PT_IDX];
                    if (PTE.present) continue;

                    PTE.present = 1;
                    PTE.write = 1;
                    PTE.page_frame_number = (ULONGLONG) PhysicalAddress >> 12;

                    address VA{};
                    VA.offset = PhysicalAddress.offset;
                    VA.p1_index = PT_IDX;
                    VA.p2_index = PD_IDX;
                    VA.p3_index = PDPT_IDX;
                    VA.p4_index = PML4_IDX;

                    Callback(VA);
                    PTE.present = 0;
                    PTE.page_frame_number = 0;
                    intrin::invlpg(VA);

                    return true;
                }
            }
        }
    }
    return false;
}

template<typename T>
T ReadPhysical(address PhysicalAddress)
{
    T result{};
    MapPhysicalToVirtual(PhysicalAddress, [&result](address VirtualAddress)
    {
        result = *static_cast<T*>(VirtualAddress);
    });
    return result;
}

address GetPhysicalAddress(address VirtualAddress, cr3 CR3)
{
    pml4e PML4E = ReadPhysical<pml4e>({(CR3.pml4_frame_number << 12) + VirtualAddress.p4_index * 8});
    if (!PML4E.present) return nullptr;

    pdpte PDPTE = ReadPhysical<pdpte>({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8});
    if (!PDPTE.present) return nullptr;

    pde PDE = ReadPhysical<pde>({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8});
    if (!PDE.present) return nullptr;

    pte PT = ReadPhysical<pte>({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8});
    if (!PT.present) return nullptr;

    return {PT.page_frame_number << 12 | VirtualAddress.offset};
}

template<typename T>
T ReadVirtualMemory(address TargetAddress, cr3 CR3)
{
    address PhysicalAddress = GetPhysicalAddress(TargetAddress, CR3);
    if (!PhysicalAddress) return false;
    return ReadPhysical<T>(PhysicalAddress);
}

PVOID EnumerateModuleBaseAddress(_EPROCESS *pEProcess, const wchar_t *ModuleName)
{
    print(INFO("Target Module Name: %ws"), ModuleName);
    if (!pEProcess) return nullptr;
    
    _KPROCESS *pKProcess = (_KPROCESS *) CONTAINING_RECORD(pEProcess, _EPROCESS, Pcb);
    cr3 CR3 = {pKProcess->DirectoryTableBase};

    _PEB *pPeb = pEProcess->Peb;
    if (!pPeb) return nullptr;

    _PEB_LDR_DATA*pLdr = ReadVirtualMemory<_PEB_LDR_DATA*>(&pPeb->Ldr, CR3);

    wchar_t pBuffer[256];
    _LDR_DATA_TABLE_ENTRY ldrEntry;
    _LIST_ENTRY moduleList = ReadVirtualMemory<_LIST_ENTRY>(&pLdr->InLoadOrderModuleList, CR3);
    _LIST_ENTRY* pHead = moduleList.Flink;
    _LIST_ENTRY* pCurrent = moduleList.Flink;

    do
    {
        ldrEntry = ReadVirtualMemory<_LDR_DATA_TABLE_ENTRY>(pCurrent, CR3);
        pCurrent = ldrEntry.InLoadOrderLinks.Flink;

        if (!(ldrEntry.DllBase && ldrEntry.BaseDllName.Length && ldrEntry.BaseDllName.Buffer))
            continue;

        if (!ReadVirtualMemory(ldrEntry.BaseDllName.Buffer, pBuffer, ldrEntry.BaseDllName.Length, CR3))
            continue;

        pBuffer[ldrEntry.BaseDllName.Length / sizeof(wchar_t)] = L'\0';
        if (!wcscmp(pBuffer, ModuleName))
            return GetPhysicalAddress(ldrEntry.DllBase, CR3);
    } while (pCurrent != pHead);
}

_EPROCESS *EnumerateProcess(const wchar_t *ProcessName)
{
    print(INFO("Target Process Name: %ws"), ProcessName);
    if (!ProcessName || ProcessName[0] == '\0')
        return nullptr;

    _EPROCESS *Process = (_EPROCESS *) win::PsInitialSystemProcess;
    _LIST_ENTRY *pHead = &(Process->ActiveProcessLinks);
    _LIST_ENTRY *pCurrent = pHead->Flink;

    while (pCurrent != pHead)
    {
        _EPROCESS *pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
        pCurrent = pCurrent->Flink;

        if (!pProcess->ImageFilePointer || !pProcess->ImageFilePointer->FileName.Length)
            continue;

        print(INFO("Process Name: %s, PID: %d, File Path: %ws"),
              pProcess->ImageFileName, pProcess->UniqueProcessId, pProcess->ImageFilePointer->FileName.Buffer);

        if (wcsstr(pProcess->ImageFilePointer->FileName.Buffer, ProcessName))
            return pProcess;
    }

    return nullptr;
}
