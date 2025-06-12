_KPROCESS *KProcess;
_KAPC_STATE KapcState;
address *pData;
char Signature[] = "48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? EB ? B8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? EB ? B8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0";

using func_type = uint64_t (__fastcall*)(address);
func_type OriginalFunc;

uint64_t __fastcall Func(uint64_t Param)
{
    print(INFO("Hit"));
    return OriginalFunc ? OriginalFunc(Param) : 0xC000001C;
}

void hook()
{
    KProcess = (_KPROCESS *)EnumerateEProcess(L"explorer.exe");
    win::KeStackAttachProcess(KProcess, &KapcState);

    address instruction = (uint64_t)SectionScan(L"", L"win32k.sys", ".text", Signature) + 0x3;
    pData = (address *) (instruction + 0x4 + *(uint32_t *) instruction);
    OriginalFunc = (func_type)xchg_ptr(pData, &Func);

    win::KeUnstackDetachProcess(&KapcState);
    print(INFO("HOOKED"));
}

void unhook()
{
    if (!pData) return;
    win::KeStackAttachProcess(KProcess, &KapcState);
    xchg_ptr(pData, OriginalFunc);
    win::KeUnstackDetachProcess(&KapcState);
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