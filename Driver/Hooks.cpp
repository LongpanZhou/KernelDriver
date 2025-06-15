#include "LazyImport.cpp"

typedef void (__fastcall *KeStackAttachProcess_t)(arch::address process_address, std::uint64_t* apc_state);
typedef void (__fastcall *KeUnstackDetachProcess_t)(std::uint64_t* apc_state);

KeStackAttachProcess_t KeStackAttachProcess;
KeUnstackDetachProcess_t KeUnstackDetachProcess;

using func_type = uint64_t (__fastcall*)(address);
func_type OriginalFunc;

_KPROCESS *KProcess;
_KAPC_STATE KapcState;
address *pData;
char Signature[] = "48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? EB ? B8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? EB ? B8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0";

uint64_t __fastcall Func(uint64_t Param)
{
    print(INFO("Hit"));
    return OriginalFunc ? OriginalFunc(Param) : 0xC000001C;
}

void Hook()
{
    // Import functions
    address ntoskrnl = EnumerateKProcess(L"ntoskrnl.exe");
    KeStackAttachProcess = (KeStackAttachProcess_t)FindFuncExports(ntoskrnl, "KeStackAttachProcess");
    KeUnstackDetachProcess = (KeUnstackDetachProcess_t)FindFuncExports(ntoskrnl, "KeUnstackDetachProcess");

    // Attach
    KProcess = (_KPROCESS *)EnumerateEProcess(L"explorer.exe");
    KeStackAttachProcess(KProcess, &KapcState);

    // Data ptr swap
    address instruction = (uint64_t)SectionScan(L"", L"win32k.sys", ".text", Signature) + 0x3;
    pData = (address *) (instruction + 0x4 + *(uint32_t *) instruction);
    OriginalFunc = (func_type)xchg_ptr(pData, &Func);

    // UnAttach
    KeUnstackDetachProcess(&KapcState);
    print(INFO("HOOKED"));
}

void UnHook()
{
    // Check if dataptr exist
    if (!pData) return;

    // Exchange Back
    KeStackAttachProcess(KProcess, &KapcState);
    xchg_ptr(pData, OriginalFunc);
    KeUnstackDetachProcess(&KapcState);
    print(INFO("UNHOOKED"));
}

/*
    extern "C"
    {
        void KeStackAttachProcess(arch::address process_address, std::uint64_t* apc_state);

        void KeUnstackDetachProcess(std::uint64_t* apc_state);
    }

    ALWAYS_INLINE arch::address xchg_ptr(arch::address target, arch::address value) {
        arch::address old = value;
        asm volatile ("xchg %0, (%1)"
                       : "=r"(old)
                       : "r"(target), "0"(value)
                       : "memory");
        return old;
    }
 */