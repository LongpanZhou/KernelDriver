// Hashs are not used but left for future if want to hide string
constexpr uint64_t TimeToSeed(const char* Time)
{
    //convert time to seed
    return
        (Time[0] - '0') * 10 * 3600 +  // Hours * 3600
        (Time[1] - '0') * 3600 +
        (Time[3] - '0') * 10 * 60 +    // Minutes * 60
        (Time[4] - '0') * 60 +
        (Time[6] - '0') * 10 +         // Seconds
        (Time[7] - '0');
}

constexpr uint64_t Hash(const char* Str, uint64_t Seed)
{
    print(INFO("Seed: %p"), Seed);
    //randomize hash with given seed
    for (; *Str; ++Str)
        Seed ^= *Str;
    print(INFO("HASH: %p"),Seed);
    return Seed;
}

address FindFuncExports(address BaseAddress, const char* FuncName)
{
    //if BaseAddress is not valid
    print(INFO("Find Func Export BaseAddress: %p"), BaseAddress);
    if (!BaseAddress) return nullptr;

    // Get Export DataDirtory
    auto *dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    print(INFO("dosHeader: %p"), dosHeader);
    if (!dosHeader) return nullptr;

    auto *ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    print(INFO("ntHeader: %p"), ntHeader);
    if (!ntHeader) return nullptr;

    auto exportSection = ntHeader->OptionalHeader.DataDirectory;
    print(INFO("exportSection: %p"), exportSection);
    if (!exportSection) return nullptr;

    // If there is no export
    auto RVA = exportSection->VirtualAddress;
    print(INFO("RVA: %p"), RVA);
    if (!RVA) return nullptr;

    // Get Export Dir
    auto exportDir = (_IMAGE_EXPORT_DIRECTORY *) (BaseAddress + RVA);
    print(INFO("exportDir: %p"), exportDir);
    if (!exportDir) return nullptr;

    // Get FuncAddress
    uint32_t* functions = (uint32_t*)(BaseAddress + exportDir->AddressOfFunctions);
    print(INFO("functions: %p"), functions);
    if (!functions) return nullptr;

    // Get NameOrdinalAddress
    uint16_t* ordinals = (uint16_t*)(BaseAddress + exportDir->AddressOfNameOrdinals);
    print(INFO("ordinals: %p"), ordinals);
    if (!ordinals) return nullptr;

    // Get NameAddress
    uint32_t* names = (uint32_t*)(BaseAddress + exportDir->AddressOfNames);
    print(INFO("names: %p"), names);
    if (!names) return nullptr;

    // Loop through export table
    for (uint32_t i = 0; i < exportDir->NumberOfNames; ++i)
    {
        const char* funcName = (const char*)(BaseAddress + names[i]);
        print(INFO("Function Name: %s"), funcName);

        if (!strcmp(funcName, FuncName))
        {
            return BaseAddress + functions[ordinals[i]];;
        }
    }

    print(ERROR("EXPORT FUNCTION NOT FOUND!"));
    return nullptr;
}