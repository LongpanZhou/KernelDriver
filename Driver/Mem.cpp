#include <wdk/wdk.hpp>
#include "Lib/structs.h"
#include "Lib/utils.h"

using namespace arch;
using namespace intrin;

namespace
{
    pdpe_1gb* PDPTE_1GB;
    pde_2mb* PDE_2MB;
    pte* PTE_4KB;

    address VA_1GB{};
    address VA_2MB{};
    address VA_4KB{};
}

enum pagesize : uint32_t
{
    Page_4KB,
    Page_2MB,
    Page_1GB,
    Page_Unmap
};

// MapPhysicalToVirtual
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize = Page_4KB)
{
    // Cache
    switch (PageSize)
    {
        case Page_4KB:
            if (PTE_4KB && VA_4KB)
            {
                PTE_4KB->page_frame_number = PhysicalAddress >> 12;
                VA_4KB.offset = PhysicalAddress.offset;

                return Callback(VA_4KB);
            }
            break;
        case Page_2MB:
            if (PDE_2MB && VA_2MB)
            {
                PDE_2MB->page_frame_number = PhysicalAddress >> 21;
                VA_2MB.offset = PhysicalAddress.offset;
                VA_2MB.p1_index = PhysicalAddress.p1_index;

                return Callback(VA_2MB);
            }
            break;
        case Page_1GB:
            if (PDPTE_1GB && VA_1GB)
            {
                PDPTE_1GB->page_frame_number = PhysicalAddress >> 30;
                VA_1GB.offset = PhysicalAddress.offset;
                VA_1GB.p1_index = PhysicalAddress.p1_index;
                VA_1GB.p2_index = PhysicalAddress.p2_index;

                return Callback(VA_1GB);
            }
            break;
        case Page_Unmap:
            if (PDPTE_1GB) PDPTE_1GB->present = 0;
            if (PDE_2MB) PDE_2MB->present = 0;
            if (PTE_4KB) PTE_4KB->present = 0;
            return true;
        default:
            print(ERROR("Invalid Type %d"), PageSize);
            return false;
    }

    // Local variables
    int PML4_IDX, PDPT_IDX, PD_IDX, PT_IDX;
    cr3 CR3 = read_cr3();
    address tmp;

    pml4e* PML4E;
    pdpe* PDPTE;
    pde* PDE;

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
        PDPTE = &((pdpe *) tmp)[PDPT_IDX];
        if (PageSize == Page_1GB)
        {
            if (PDPTE->present) continue;

            PDPTE_1GB = (pdpe_1gb*)PDPTE;
            PDPTE_1GB->present = 1;
            PDPTE_1GB->write = 1;
            PDPTE_1GB->page_size = 1;
            PDPTE_1GB->page_frame_number = PhysicalAddress >> 30;

            VA_1GB.offset = PhysicalAddress.offset;
            VA_1GB.p1_index = PhysicalAddress.p1_index;
            VA_1GB.p2_index = PhysicalAddress.p2_index;
            VA_1GB.p3_index = PDPT_IDX;
            VA_1GB.p4_index = PML4_IDX;

            return Callback(VA_1GB);
        }

        if (PDPTE->present) break;
    }

    // PD
    tmp = win::MmGetVirtualForPhysical({PDPTE->page_frame_number << 12});
    for (PD_IDX = 0; PD_IDX < 512; ++PD_IDX)
    {
        PDE = &((pde *) tmp)[PD_IDX];
        if (PageSize == Page_2MB)
        {
            if (PDE->present) continue;

            PDE_2MB = (pde_2mb *)PDE;
            PDE_2MB->present = 1;
            PDE_2MB->write = 1;
            PDE_2MB->page_size = 1;
            PDE_2MB->page_frame_number = PhysicalAddress >> 21;

            VA_2MB.offset = PhysicalAddress.offset;
            VA_2MB.p1_index = PhysicalAddress.p1_index;
            VA_2MB.p2_index = PD_IDX;
            VA_2MB.p3_index = PDPT_IDX;
            VA_2MB.p4_index = PML4_IDX;

            return Callback(VA_2MB);
        }

        if (PDE->present) break;
    }

    // PT
    tmp = win::MmGetVirtualForPhysical({PDE->page_frame_number << 12});
    for (PT_IDX = 0; PT_IDX < 512; ++PT_IDX)
    {
        PTE_4KB = &((pte *) tmp)[PT_IDX];
        if (PTE_4KB->present) continue;

        PTE_4KB->present = 1;
        PTE_4KB->write = 1;
        PTE_4KB->page_frame_number = PhysicalAddress >> 12;

        VA_4KB.offset = PhysicalAddress.offset;
        VA_4KB.p1_index = PT_IDX;
        VA_4KB.p2_index = PD_IDX;
        VA_4KB.p3_index = PDPT_IDX;
        VA_4KB.p4_index = PML4_IDX;

        return Callback(VA_4KB);
    }

    return false;
}

// Read Physical Memory
template<typename T>
T ReadPhysical(address PhysicalAddress, pagesize PageSize = Page_4KB)
{
    T tmp{};
    MapPhysicalToVirtual(PhysicalAddress,
        [&tmp](address VirtualAddress)
        {
            invlpg(VirtualAddress);
            memcpy(&tmp, VirtualAddress, sizeof(T));
            return true;
        },
        PageSize
        );
    return tmp;
}

bool ReadPhysical(address PhysicalAddress, void* pBuffer, size_t Size, pagesize PageSize = Page_4KB)
{
    return MapPhysicalToVirtual(PhysicalAddress,
            [pBuffer, Size](address VirtualAddress)
            {
                invlpg(VirtualAddress);
                memcpy(pBuffer, VirtualAddress, Size);
                return true;
            },
            PageSize
    );
}

// Translate Virtual Address to Physical Address
std::pair<address, pagesize> GetPhysicalAddress(address VirtualAddress, cr3 CR3)
{
    // Variables
    static pml4e PML4ETable[512];
    pml4e PML4E = PML4ETable[VirtualAddress.p4_index];

    // Check Cache
    if (!PML4E.present)
    {
        ReadPhysical({(CR3.pml4_frame_number << 12)}, &PML4ETable, sizeof(PML4ETable));
        PML4E = PML4ETable[VirtualAddress.p4_index];
        if (!PML4E) return {};
    }

    // Translation...       Type 0: 4KB, Type 1: 2MB, Type 2: 1GB
    auto PDPTE = ReadPhysical<pdpe>({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8});
    if (!PDPTE) return {};
    if (((pdpe_1gb)PDPTE).page_size)
        return {((pdpe_1gb)PDPTE).page_frame_number << 30 | VirtualAddress.offset_1gb(), Page_1GB};

    auto PDE = ReadPhysical<pde>({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8});
    if (!PDE) return {};
    if (((pde_2mb)PDE).page_size)
        return {((pde_2mb)PDE).page_frame_number << 21 | VirtualAddress.offset_2mb(), Page_2MB};

    auto PT = ReadPhysical<pte>({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8});
    if (!PT) return {};
    return {PT.page_frame_number << 12 | VirtualAddress.offset, Page_4KB};
}

// Read Virtual Memory
template<typename T>
T ReadVirtualMemory(address TargetAddress, cr3 CR3)
{
    std::pair<address,pagesize> tmp = GetPhysicalAddress(TargetAddress, CR3);
    if (!tmp.first) return T{};
    return ReadPhysical<T>(tmp.first, tmp.second);
}

bool ReadVirtualMemory(address VirtualAddress, cr3 CR3, void *pBuffer, size_t Size)
{
    std::pair<address,pagesize> tmp = GetPhysicalAddress(VirtualAddress, CR3);
    if (!tmp.first) return false;
    return ReadPhysical(tmp.first, pBuffer, Size, tmp.second);
}