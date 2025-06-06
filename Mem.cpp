#include "Lib/structs.h"
#include "Lib/utils.h"

using namespace arch;
using namespace intrin;

// MapPhysicalToVirtual
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