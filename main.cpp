#include "structs.h"
#include "utils.h"

using namespace arch;
using namespace intrin;

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

// MapPhysicalToVirtual (Very bad impl, need to add 2MB pages support and caching)
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, int type)
{
    // Global variables
    static pml4e* PML4E;
    static pdpte_1gb* PDPTE;
    static pde_2mb* PDE;
    static pte* PTE;

    static address VA_1GB;
    static address VA_2MB;
    static address VA_4KB;

    // Cache
    switch (type)
    {
        case 0:
            if (PTE)
            {
                PTE->page_frame_number = PhysicalAddress >> 12;
                VA_4KB.offset = PhysicalAddress.offset;

                invlpg(VA_4KB);
                Callback(VA_4KB);
                return true;
            }
            break;
        case 1:
            if (PDE)
            {
                PDE->page_frame_number = PhysicalAddress >> 21;
                VA_2MB.offset = PhysicalAddress.offset;
                VA_2MB.p1_index = PhysicalAddress.p1_index;

                invlpg(VA_2MB);
                Callback(VA_2MB);
                return true;
            }
            break;
        case 2:
            if (PDPTE)
            {
                PDPTE->page_frame_number = PhysicalAddress >> 30;
                VA_1GB.offset = PhysicalAddress.offset;
                VA_1GB.p1_index = PhysicalAddress.p1_index;
                VA_1GB.p2_index = PhysicalAddress.p2_index;

                invlpg(VA_1GB);
                Callback(VA_1GB);
                return true;
            }
            break;
    }

    // Local variables
    int PML4_IDX, PDPT_IDX, PD_IDX, PT_IDX;
    address tmp;
    cr3 CR3 = read_cr3();

    // PML4
    tmp = win::MmGetVirtualForPhysical({CR3.pml4_frame_number << 12});
    for (PML4_IDX = 0; PML4_IDX < 512; ++PML4_IDX)
    {
        PML4E = &((pml4e *)tmp)[PML4_IDX];
        if (PML4E->present) break;
    }

    // PDPT
    tmp = win::MmGetVirtualForPhysical({PML4E->page_frame_number << 12});
    for (PDPT_IDX = 0; PDPT_IDX < 512; ++PDPT_IDX)
    {
        PDPTE = &((pdpte_1gb *) tmp)[PDPT_IDX];
        if (type == 2)
        {
            if (PDPTE->present) continue;
            print("HIT");

            PDPTE->present = 1;
            PDPTE->write = 1;
            PDPTE->page_size = 1;
            PDPTE->page_frame_number = PhysicalAddress >> 30;

            VA_1GB.offset = PhysicalAddress.offset;
            VA_1GB.p1_index = PhysicalAddress.p1_index;
            VA_1GB.p2_index = PhysicalAddress.p2_index;
            VA_1GB.p3_index = PDPT_IDX;
            VA_1GB.p4_index = PML4_IDX;

            invlpg(VA_1GB);
            Callback(VA_1GB);
            return true;
        }

        if (PDPTE->present) break;
    }

    // PD
    tmp = win::MmGetVirtualForPhysical({((pdpte*)PDPTE)->page_frame_number << 12});
    for (PD_IDX = 0; PD_IDX < 512; ++PD_IDX)
    {
        PDE = &((pde_2mb *) tmp)[PD_IDX];
        if (type == 1)
        {
            if (PDE->present) continue;
            print("HIT");

            PDE->present = 1;
            PDE->write = 1;
            PDE->page_size = 1;
            PDE->page_frame_number = PhysicalAddress >> 21;

            VA_2MB.offset = PhysicalAddress.offset;
            VA_2MB.p1_index = PhysicalAddress.p1_index;
            VA_2MB.p2_index = PD_IDX;
            VA_2MB.p3_index = PDPT_IDX;
            VA_2MB.p4_index = PML4_IDX;

            invlpg(VA_2MB);
            Callback(VA_2MB);
            return true;
        }

        if (PDE->present) break;
    }

    // PT
    tmp = win::MmGetVirtualForPhysical({((pde*)PDE)->page_frame_number << 12});
    for (PT_IDX = 0; PT_IDX < 512; ++PT_IDX)
    {
        PTE = &((pte *) tmp)[PT_IDX];
        if (PTE->present) continue;

        PTE->present = 1;
        PTE->write = 1;
        PTE->page_frame_number = PhysicalAddress >> 12;

        VA_4KB.offset = PhysicalAddress.offset;
        VA_4KB.p1_index = PT_IDX;
        VA_4KB.p2_index = PD_IDX;
        VA_4KB.p3_index = PDPT_IDX;
        VA_4KB.p4_index = PML4_IDX;

        invlpg(VA_4KB);
        Callback(VA_4KB);
        return true;
    }

    return false;
}

// Read Physical Memory
template<typename T>
T ReadPhysical(address PhysicalAddress, int type = 0)
{
    T tmp{};
    MapPhysicalToVirtual(PhysicalAddress,
        [&tmp](address VirtualAddress)
        {memcpy(&tmp, VirtualAddress, sizeof(T));},
        (PhysicalAddress>>7) & 1 ? type : 0
        );
    return tmp;
}

bool ReadPhysical(address PhysicalAddress, void* pBuffer, size_t Size, int type = 0)
{
    return MapPhysicalToVirtual(PhysicalAddress,
            [pBuffer, Size](address VirtualAddress)
            {memcpy(pBuffer, VirtualAddress, Size);},
            (PhysicalAddress>>7) & 1 ? type : 0
    );
}

// Translate Virtual Address to Physical Address
address GetPhysicalAddress(address VirtualAddress, cr3 CR3)
{
    // Variables
    static pml4e PML4ETable[512];
    pml4e PML4E = PML4ETable[VirtualAddress.p4_index];

    // Check Cache
    if (!PML4E.present)
    {
        ReadPhysical({(CR3.pml4_frame_number << 12) + VirtualAddress.p4_index * 8}, &PML4ETable, sizeof(PML4ETable));
        PML4E = PML4ETable[VirtualAddress.p4_index];
        if (!PML4E) return nullptr;
    }

    // Translation...       Type 0: 4KB, Type 1: 2MB, Type 2: 1GB
    auto PDPTE = ReadPhysical<pdpte>({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8});
    if (!PDPTE) return nullptr;
    if (((pdpte_1gb)PDPTE).page_size) return ReadPhysical<address>(PDPTE, 2);

    auto PDE = ReadPhysical<pde>({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8});
    if (!PDE) return nullptr;
    if (((pde_2mb)PDE).page_size) return ReadPhysical<address>(PDE, 1);

    auto PT = ReadPhysical<pte>({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8});
    if (!PT) return nullptr;
    return {PT.page_frame_number << 12 | VirtualAddress.offset};
}

// Read Virtual Memory
template<typename T>
T ReadVirtualMemory(address TargetAddress, cr3 CR3)
{
    address PhysicalAddress = GetPhysicalAddress(TargetAddress, CR3);
    if (!PhysicalAddress) return T{};
    return ReadPhysical<T>(PhysicalAddress);
}

bool ReadVirtualMemory(address VirtualAddress, cr3 CR3, void *pBuffer, size_t Size)
{
    address PhysicalAddress = GetPhysicalAddress(VirtualAddress, CR3);
    if (!PhysicalAddress) return false;
    return ReadPhysical(PhysicalAddress, pBuffer, Size);
}

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
