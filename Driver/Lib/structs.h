#pragma once
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

#include <wdk/wdk.hpp>

#define BOOL bool
#define VOID void
#define PVOID void*

#define UCHAR uint8_t
#define USHORT uint16_t
#define ULONG uint32_t
#define ULONGLONG uint64_t

#define CHAR int8_t
#define SHORT int16_t
#define LONG int32_t
#define LONGLONG int64_t

#define _UNICODE_STRING UNICODE_STRING

#define CONTAINING_RECORD(address, type, field) ((type *)((uint64_t)(address) - (uint64_t)(&((type *)0)->field)))

// PE HEADER BS
//0x8 bytes (sizeof)
struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;                                                   //0x0
    ULONG Size;                                                             //0x4
};

// 0x28 bytes (sizeof)
struct _IMAGE_EXPORT_DIRECTORY
{
    ULONG  Characteristics;                                                 //0x0
    ULONG  TimeDateStamp;                                                   //0x4
    USHORT MajorVersion;                                                    //0x8
    USHORT MinorVersion;                                                    //0xa
    ULONG  Name;                                                            //0xc
    ULONG  Base;                                                            //0x10
    ULONG  NumberOfFunctions;                                               //0x14
    ULONG  NumberOfNames;                                                   //0x18
    ULONG  AddressOfFunctions;                                              //0x1c
    ULONG  AddressOfNames;                                                  //0x20
    ULONG  AddressOfNameOrdinals;                                           //0x24
};


//0x40 bytes (sizeof)
struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;                                                         //0x0
    USHORT e_cblp;                                                          //0x2
    USHORT e_cp;                                                            //0x4
    USHORT e_crlc;                                                          //0x6
    USHORT e_cparhdr;                                                       //0x8
    USHORT e_minalloc;                                                      //0xa
    USHORT e_maxalloc;                                                      //0xc
    USHORT e_ss;                                                            //0xe
    USHORT e_sp;                                                            //0x10
    USHORT e_csum;                                                          //0x12
    USHORT e_ip;                                                            //0x14
    USHORT e_cs;                                                            //0x16
    USHORT e_lfarlc;                                                        //0x18
    USHORT e_ovno;                                                          //0x1a
    USHORT e_res[4];                                                        //0x1c
    USHORT e_oemid;                                                         //0x24
    USHORT e_oeminfo;                                                       //0x26
    USHORT e_res2[10];                                                      //0x28
    LONG e_lfanew;                                                          //0x3c
};

//0x14 bytes (sizeof)
struct _IMAGE_FILE_HEADER
{
    USHORT Machine;                                                         //0x0
    USHORT NumberOfSections;                                                //0x2
    ULONG TimeDateStamp;                                                    //0x4
    ULONG PointerToSymbolTable;                                             //0x8
    ULONG NumberOfSymbols;                                                  //0xc
    USHORT SizeOfOptionalHeader;                                            //0x10
    USHORT Characteristics;                                                 //0x12
};

//0xf0 bytes (sizeof)
struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;                                                           //0x0
    UCHAR MajorLinkerVersion;                                               //0x2
    UCHAR MinorLinkerVersion;                                               //0x3
    ULONG SizeOfCode;                                                       //0x4
    ULONG SizeOfInitializedData;                                            //0x8
    ULONG SizeOfUninitializedData;                                          //0xc
    ULONG AddressOfEntryPoint;                                              //0x10
    ULONG BaseOfCode;                                                       //0x14
    ULONGLONG ImageBase;                                                    //0x18
    ULONG SectionAlignment;                                                 //0x20
    ULONG FileAlignment;                                                    //0x24
    USHORT MajorOperatingSystemVersion;                                     //0x28
    USHORT MinorOperatingSystemVersion;                                     //0x2a
    USHORT MajorImageVersion;                                               //0x2c
    USHORT MinorImageVersion;                                               //0x2e
    USHORT MajorSubsystemVersion;                                           //0x30
    USHORT MinorSubsystemVersion;                                           //0x32
    ULONG Win32VersionValue;                                                //0x34
    ULONG SizeOfImage;                                                      //0x38
    ULONG SizeOfHeaders;                                                    //0x3c
    ULONG CheckSum;                                                         //0x40
    USHORT Subsystem;                                                       //0x44
    USHORT DllCharacteristics;                                              //0x46
    ULONGLONG SizeOfStackReserve;                                           //0x48
    ULONGLONG SizeOfStackCommit;                                            //0x50
    ULONGLONG SizeOfHeapReserve;                                            //0x58
    ULONGLONG SizeOfHeapCommit;                                             //0x60
    ULONG LoaderFlags;                                                      //0x68
    ULONG NumberOfRvaAndSizes;                                              //0x6c
    struct _IMAGE_DATA_DIRECTORY DataDirectory[16];                         //0x70
};

//0x108 bytes (sizeof)
struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;                                                        //0x0
    struct _IMAGE_FILE_HEADER FileHeader;                                   //0x4
    struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;                         //0x18
};

//0x28 bytes (sizeof)
struct _IMAGE_SECTION_HEADER
{
    UCHAR Name[8];                                                          //0x0
    union
    {
        ULONG PhysicalAddress;                                              //0x8
        ULONG VirtualSize;                                                  //0x8
    } Misc;                                                                 //0x8
    ULONG VirtualAddress;                                                   //0xc
    ULONG SizeOfRawData;                                                    //0x10
    ULONG PointerToRawData;                                                 //0x14
    ULONG PointerToRelocations;                                             //0x18
    ULONG PointerToLinenumbers;                                             //0x1c
    USHORT NumberOfRelocations;                                             //0x20
    USHORT NumberOfLinenumbers;                                             //0x22
    ULONG Characteristics;                                                  //0x24
};

// Kernel BS
//0x8 bytes (sizeof)
struct _SINGLE_LIST_ENTRY
{
    struct _SINGLE_LIST_ENTRY* Next;                                        //0x0
};

//0x10 bytes (sizeof)
struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;                                              //0x0
    struct _LIST_ENTRY* Blink;                                              //0x8
};

//0x8 bytes (sizeof)
struct _WNF_STATE_NAME
{
    ULONG Data[2];                                                          //0x0
};

//0x8 bytes (sizeof)
struct _EX_RUNDOWN_REF
{
    union
    {
        ULONGLONG Count;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x8 bytes (sizeof)
union _ULARGE_INTEGER
{
    struct
    {
        ULONG LowPart;                                                      //0x0
        ULONG HighPart;                                                     //0x4
    };
    struct
    {
        ULONG LowPart;                                                      //0x0
        ULONG HighPart;                                                     //0x4
    } u;                                                                    //0x0
    ULONGLONG QuadPart;                                                     //0x0
};

//0x8 bytes (sizeof)
union _LARGE_INTEGER
{
    struct
    {
        ULONG LowPart;                                                      //0x0
        LONG HighPart;                                                      //0x4
    };
    struct
    {
        ULONG LowPart;                                                      //0x0
        LONG HighPart;                                                      //0x4
    } u;                                                                    //0x0
    LONGLONG QuadPart;                                                      //0x0
};

//0x18 bytes (sizeof)
struct _DISPATCHER_HEADER
{
    union
    {
        volatile LONG Lock;                                                 //0x0
        LONG LockNV;                                                        //0x0
        struct
        {
            UCHAR Type;                                                     //0x0
            UCHAR Signalling;                                               //0x1
            UCHAR Size;                                                     //0x2
            UCHAR Reserved1;                                                //0x3
        };
        struct
        {
            UCHAR TimerType;                                                //0x0
            union
            {
                UCHAR TimerControlFlags;                                    //0x1
                struct
                {
                    UCHAR Absolute:1;                                       //0x1
                    UCHAR Wake:1;                                           //0x1
                    UCHAR EncodedTolerableDelay:6;                          //0x1
                };
            };
            UCHAR Hand;                                                     //0x2
            union
            {
                UCHAR TimerMiscFlags;                                       //0x3
                struct
                {
                    UCHAR Index:6;                                          //0x3
                    UCHAR Inserted:1;                                       //0x3
                    volatile UCHAR Expired:1;                               //0x3
                };
            };
        };
        struct
        {
            UCHAR Timer2Type;                                               //0x0
            union
            {
                UCHAR Timer2Flags;                                          //0x1
                struct
                {
                    UCHAR Timer2Inserted:1;                                 //0x1
                    UCHAR Timer2Expiring:1;                                 //0x1
                    UCHAR Timer2CancelPending:1;                            //0x1
                    UCHAR Timer2SetPending:1;                               //0x1
                    UCHAR Timer2Running:1;                                  //0x1
                    UCHAR Timer2Disabled:1;                                 //0x1
                    UCHAR Timer2ReservedFlags:2;                            //0x1
                };
            };
            UCHAR Timer2ComponentId;                                        //0x2
            UCHAR Timer2RelativeId;                                         //0x3
        };
        struct
        {
            UCHAR QueueType;                                                //0x0
            union
            {
                UCHAR QueueControlFlags;                                    //0x1
                struct
                {
                    UCHAR Abandoned:1;                                      //0x1
                    UCHAR DisableIncrement:1;                               //0x1
                    UCHAR QueueReservedControlFlags:6;                      //0x1
                };
            };
            UCHAR QueueSize;                                                //0x2
            UCHAR QueueReserved;                                            //0x3
        };
        struct
        {
            UCHAR ThreadType;                                               //0x0
            UCHAR ThreadReserved;                                           //0x1
            union
            {
                UCHAR ThreadControlFlags;                                   //0x2
                struct
                {
                    UCHAR CycleProfiling:1;                                 //0x2
                    UCHAR CounterProfiling:1;                               //0x2
                    UCHAR GroupScheduling:1;                                //0x2
                    UCHAR AffinitySet:1;                                    //0x2
                    UCHAR Tagged:1;                                         //0x2
                    UCHAR EnergyProfiling:1;                                //0x2
                    UCHAR SchedulerAssist:1;                                //0x2
                    UCHAR ThreadReservedControlFlags:1;                     //0x2
                };
            };
            union
            {
                UCHAR DebugActive;                                          //0x3
                struct
                {
                    UCHAR ActiveDR7:1;                                      //0x3
                    UCHAR Instrumented:1;                                   //0x3
                    UCHAR Minimal:1;                                        //0x3
                    UCHAR Reserved4:2;                                      //0x3
                    UCHAR AltSyscall:1;                                     //0x3
                    UCHAR UmsScheduled:1;                                   //0x3
                    UCHAR UmsPrimary:1;                                     //0x3
                };
            };
        };
        struct
        {
            UCHAR MutantType;                                               //0x0
            UCHAR MutantSize;                                               //0x1
            UCHAR DpcActive;                                                //0x2
            UCHAR MutantReserved;                                           //0x3
        };
    };
    LONG SignalState;                                                       //0x4
    struct _LIST_ENTRY WaitListHead;                                        //0x8
};

//0x18 bytes (sizeof)
struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
};

//0x30 bytes (sizeof)
struct _KAPC_STATE
{
    uint64_t* operator&() noexcept {return (uint64_t*)this;}

    struct _LIST_ENTRY ApcListHead[2];                                      //0x0
    struct _KPROCESS* Process;                                              //0x20
    union
    {
        UCHAR InProgressFlags;                                              //0x28
        struct
        {
            UCHAR KernelApcInProgress:1;                                    //0x28
            UCHAR SpecialApcInProgress:1;                                   //0x28
        };
    };
    UCHAR KernelApcPending;                                                 //0x29
    union
    {
        UCHAR UserApcPendingAll;                                            //0x2a
        struct
        {
            UCHAR SpecialUserApcPending:1;                                  //0x2a
            UCHAR UserApcPending:1;                                         //0x2a
        };
    };
};

//0xd8 bytes (sizeof)
struct _FILE_OBJECT
{
    SHORT Type;                                                             //0x0
    SHORT Size;                                                             //0x2
    struct _DEVICE_OBJECT* DeviceObject;                                    //0x8
    struct _VPB* Vpb;                                                       //0x10
    VOID* FsContext;                                                        //0x18
    VOID* FsContext2;                                                       //0x20
    struct _SECTION_OBJECT_POINTERS* SectionObjectPointer;                  //0x28
    VOID* PrivateCacheMap;                                                  //0x30
    LONG FinalStatus;                                                       //0x38
    struct _FILE_OBJECT* RelatedFileObject;                                 //0x40
    UCHAR LockOperation;                                                    //0x48
    UCHAR DeletePending;                                                    //0x49
    UCHAR ReadAccess;                                                       //0x4a
    UCHAR WriteAccess;                                                      //0x4b
    UCHAR DeleteAccess;                                                     //0x4c
    UCHAR SharedRead;                                                       //0x4d
    UCHAR SharedWrite;                                                      //0x4e
    UCHAR SharedDelete;                                                     //0x4f
    ULONG Flags;                                                            //0x50
    struct _UNICODE_STRING FileName;                                        //0x58
    union _LARGE_INTEGER CurrentByteOffset;                                 //0x68
    ULONG Waiters;                                                          //0x70
    ULONG Busy;                                                             //0x74
    VOID* LastLock;                                                         //0x78
    struct _KEVENT Lock;                                                    //0x80
    struct _KEVENT Event;                                                   //0x98
    struct _IO_COMPLETION_CONTEXT* CompletionContext;                       //0xb0
    ULONGLONG IrpListLock;                                                  //0xb8
    struct _LIST_ENTRY IrpList;                                             //0xc0
    VOID* FileObjectExtension;                                              //0xd0
};

//0x18 bytes (sizeof)
struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red:1;                                                    //0x10
            UCHAR Balance:2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
};

//0x4 bytes (sizeof)
enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonEnclavePrimary = 7,
    LoadReasonEnclaveDependency = 8,
    LoadReasonUnknown = -1
};

//0xa0 bytes (sizeof)
struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel:4;                                            //0x6e
        USHORT SignatureType:3;                                             //0x6e
        USHORT Unused:9;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    VOID* Spare;                                                            //0x90
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
};

//0x120 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
};

//0x58 bytes (sizeof)
struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
};

//0x7c8 bytes (sizeof)
struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ProcessPreviouslyThrottled : 1;                             //0x50
            ULONG ProcessCurrentlyThrottled : 1;                              //0x50
            ULONG ProcessImagesHotPatched : 1;                                //0x50
            ULONG ReservedBits0 : 24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID(*PostProcessInitRoutine)();                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[4];                                                 //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pUnused;                                                          //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG LibLoaderTracingEnabled : 1;                                //0x378
            ULONG SpareTracingBits : 29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct _LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x7c0
            ULONG Reserved : 31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
};

//0x8 bytes (sizeof)
struct VirtualAddress
{
    union
    {
        struct
        {
            ULONGLONG Physical_Page_Offset : 12;                           //0x0
            ULONGLONG P1_IDX : 9;                                          //0x0
			ULONGLONG P2_IDX : 9;                                          //0x0
            ULONGLONG P3_IDX : 9;                                          //0x0
            ULONGLONG P4_IDX : 9;                                          //0x0
			ULONGLONG Reserved : 16;                                       //0x0
        };
		ULONGLONG Value;                                                    //0x0
	};
};

//0x8 bytes (sizeof)
struct _RTL_AVL_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
};

//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x4 bytes (sizeof)
union _KSTACK_COUNT
{
    LONG Value;                                                             //0x0
    ULONG State : 3;                                                          //0x0
    ULONG StackCount : 29;                                                    //0x0
};

//0x4 bytes (sizeof)
struct _MMSUPPORT_FLAGS
{
    union
    {
        struct
        {
            UCHAR WorkingSetType : 3;                                         //0x0
            UCHAR Reserved0 : 3;                                              //0x0
            UCHAR MaximumWorkingSetHard : 1;                                  //0x0
            UCHAR MinimumWorkingSetHard : 1;                                  //0x0
            UCHAR SessionMaster : 1;                                          //0x1
            UCHAR TrimmerState : 2;                                           //0x1
            UCHAR Reserved : 1;                                               //0x1
            UCHAR PageStealers : 4;                                           //0x1
        };
        USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union
    {
        struct
        {
            UCHAR WsleDeleted : 1;                                            //0x3
            UCHAR SvmEnabled : 1;                                             //0x3
            UCHAR ForceAge : 1;                                               //0x3
            UCHAR ForceTrim : 1;                                              //0x3
            UCHAR NewMaximum : 1;                                             //0x3
            UCHAR CommitReleaseState : 2;                                     //0x3
        };
        UCHAR u2;                                                           //0x3
    };
};

//0x8 bytes (sizeof)
struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;                                                   //0x0
    ULONG LowEdgeFilter;                                                    //0x4
};

//0x80 bytes (sizeof)
struct _MMSUPPORT_SHARED
{
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    VOID* WsSwapSupport;                                                    //0x18
    VOID* CommitReleaseContext;                                             //0x20
    VOID* AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    ULONGLONG WorkingSetCoreLock;                                           //0x40
    VOID* ShadowMapping;                                                    //0x48
};

//0xc0 bytes (sizeof)
struct _MMSUPPORT_INSTANCE
{
    ULONG NextPageColor;                                                    //0x0
    ULONG PageFaultCount;                                                   //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    ULONGLONG AgeDistribution[8];                                           //0x28
    struct _KGATE* ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG WorkingSetLeafSize;                                           //0x78
    ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
    ULONGLONG WorkingSetSize;                                               //0x88
    ULONGLONG WorkingSetPrivateSize;                                        //0x90
    ULONGLONG MaximumWorkingSetSize;                                        //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT LastTrimStamp;                                                   //0xac
    USHORT PartitionId;                                                     //0xae
    ULONGLONG SelfmapLock;                                                  //0xb0
    struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
};

//0xa8 bytes (sizeof)
struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
};

//0x1 bytes (sizeof)
union _KEXECUTE_OPTIONS
{
    UCHAR ExecuteDisable : 1;                                                 //0x0
    UCHAR ExecuteEnable : 1;                                                  //0x0
    UCHAR DisableThunkEmulation : 1;                                          //0x0
    UCHAR Permanent : 1;                                                      //0x0
    UCHAR ExecuteDispatchEnable : 1;                                          //0x0
    UCHAR ImageDispatchEnable : 1;                                            //0x0
    UCHAR DisableExceptionChainValidation : 1;                                //0x0
    UCHAR Spare : 1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
};

//0x10 bytes (sizeof)
struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
    struct _RTL_AVL_TREE Tree;                                              //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x8
};

//0x30 bytes (sizeof)
struct _PS_PROCESS_WAKE_INFORMATION
{
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
};

//0x8 bytes (sizeof)
union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    ULONGLONG DelayMs : 30;                                                   //0x0
    ULONGLONG CoalescingWindowMs : 30;                                        //0x0
    ULONGLONG Reserved : 1;                                                   //0x0
    ULONGLONG NewTimerWheel : 1;                                              //0x0
    ULONGLONG Retry : 1;                                                      //0x0
    ULONGLONG Locked : 1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
};

//0x1 bytes (sizeof)
struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;                                                        //0x0
        struct
        {
            UCHAR Type : 3;                                                   //0x0
            UCHAR Audit : 1;                                                  //0x0
            UCHAR Signer : 4;                                                 //0x0
        };
    };
};

//0x20 bytes (sizeof)
struct _ALPC_PROCESS_CONTEXT
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};

//0x140 bytes (sizeof)
struct _MMSUPPORT_FULL
{
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc0
};

//0x8 bytes (sizeof)
struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
};

//0x8 bytes (sizeof)
struct _EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt : 4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

//0x438 bytes (sizeof) 
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    ULONGLONG AffinityPadding[12];                                          //0xf8
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
    ULONGLONG ActiveProcessorsPadding[12];                                  //0x218
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x278
            ULONG DisableBoost : 1;                                           //0x278
            ULONG DisableQuantum : 1;                                         //0x278
            ULONG DeepFreeze : 1;                                             //0x278
            ULONG TimerVirtualization : 1;                                    //0x278
            ULONG CheckStackExtents : 1;                                      //0x278
            ULONG CacheIsolationEnabled : 1;                                  //0x278
            ULONG PpmPolicy : 3;                                              //0x278
            ULONG VaSpaceDeleted : 1;                                         //0x278
            ULONG ReservedFlags : 21;                                         //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    union _KEXECUTE_OPTIONS Flags;                                          //0x283
    USHORT ThreadSeed[20];                                                  //0x284
    USHORT ThreadSeedPadding[12];                                           //0x2ac
    USHORT IdealProcessor[20];                                              //0x2c4
    USHORT IdealProcessorPadding[12];                                       //0x2ec
    USHORT IdealNode[20];                                                   //0x304
    USHORT IdealNodePadding[12];                                            //0x32c
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    volatile union _KSTACK_COUNT StackCount;                                 //0x348
    struct _LIST_ENTRY ProcessListEntry;                                    //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    VOID* InstrumentationCallback;                                          //0x3d8
    union
    {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct
        {
            ULONGLONG SecureProcess : 1;                                      //0x3e0
            ULONGLONG Unused : 1;                                             //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG EndPadding[8];                                                //0x3f8
};

//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x460
            ULONG AccountingFolded : 1;                                       //0x460
            ULONG NewProcessReported : 1;                                     //0x460
            ULONG ExitProcessReported : 1;                                    //0x460
            ULONG ReportCommitChanges : 1;                                    //0x460
            ULONG LastReportMemory : 1;                                       //0x460
            ULONG ForceWakeCharge : 1;                                        //0x460
            ULONG CrossSessionCreate : 1;                                     //0x460
            ULONG NeedsHandleRundown : 1;                                     //0x460
            ULONG RefTraceEnabled : 1;                                        //0x460
            ULONG PicoCreated : 1;                                            //0x460
            ULONG EmptyJobEvaluated : 1;                                      //0x460
            ULONG DefaultPagePriority : 3;                                    //0x460
            ULONG PrimaryTokenFrozen : 1;                                     //0x460
            ULONG ProcessVerifierTarget : 1;                                  //0x460
            ULONG RestrictSetThreadContext : 1;                               //0x460
            ULONG AffinityPermanent : 1;                                      //0x460
            ULONG AffinityUpdateEnable : 1;                                   //0x460
            ULONG PropagateNode : 1;                                          //0x460
            ULONG ExplicitAffinity : 1;                                       //0x460
            ULONG ProcessExecutionState : 2;                                  //0x460
            ULONG EnableReadVmLogging : 1;                                    //0x460
            ULONG EnableWriteVmLogging : 1;                                   //0x460
            ULONG FatalAccessTerminationRequested : 1;                        //0x460
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
            ULONG ProcessStateChangeRequest : 2;                              //0x460
            ULONG ProcessStateChangeInProgress : 1;                           //0x460
            ULONG InPrivate : 1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;                                                        //0x464
        struct
        {
            ULONG CreateReported : 1;                                         //0x464
            ULONG NoDebugInherit : 1;                                         //0x464
            ULONG ProcessExiting : 1;                                         //0x464
            ULONG ProcessDelete : 1;                                          //0x464
            ULONG ManageExecutableMemoryWrites : 1;                           //0x464
            ULONG VmDeleted : 1;                                              //0x464
            ULONG OutswapEnabled : 1;                                         //0x464
            ULONG Outswapped : 1;                                             //0x464
            ULONG FailFastOnCommitFail : 1;                                   //0x464
            ULONG Wow64VaSpace4Gb : 1;                                        //0x464
            ULONG AddressSpaceInitialized : 2;                                //0x464
            ULONG SetTimerResolution : 1;                                     //0x464
            ULONG BreakOnTermination : 1;                                     //0x464
            ULONG DeprioritizeViews : 1;                                      //0x464
            ULONG WriteWatch : 1;                                             //0x464
            ULONG ProcessInSession : 1;                                       //0x464
            ULONG OverrideAddressSpace : 1;                                   //0x464
            ULONG HasAddressSpace : 1;                                        //0x464
            ULONG LaunchPrefetched : 1;                                       //0x464
            ULONG Background : 1;                                             //0x464
            ULONG VmTopDown : 1;                                              //0x464
            ULONG ImageNotifyDone : 1;                                        //0x464
            ULONG PdeUpdateNeeded : 1;                                        //0x464
            ULONG VdmAllowed : 1;                                             //0x464
            ULONG ProcessRundown : 1;                                         //0x464
            ULONG ProcessInserted : 1;                                        //0x464
            ULONG DefaultIoPriority : 3;                                      //0x464
            ULONG ProcessSelfDelete : 1;                                      //0x464
            ULONG SetTimerResolutionLink : 1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union
    {
        VOID* ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState : 3;                                     //0x4b0
    };
    struct _EX_FAST_REF Token;                                              //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    struct _RTL_AVL_TREE CloneRoot;                                         //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    VOID* SectionObject;                                                    //0x518
    VOID* SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    VOID* Win32WindowStation;                                               //0x538
    VOID* InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    VOID* DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    VOID* DeviceMap;                                                        //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    VOID* SecurityPort;                                                     //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0
    struct _LIST_ENTRY JobLinks;                                            //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    struct _EX_FAST_REF PrefetchTrace;                                      //0x600
    VOID* LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _MMSUPPORT_FULL Vm;                                              //0x680
    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    struct _RTL_AVL_TREE VadRoot;                                           //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x860
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    struct _PS_PROTECTION Protection;                                       //0x87a
    UCHAR HangCount : 3;                                                      //0x87b
    UCHAR GhostCount : 3;                                                     //0x87b
    UCHAR PrefilterException : 1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal : 1;                                                //0x87c
            ULONG ReplacingPageRoot : 1;                                      //0x87c
            ULONG Crashed : 1;                                                //0x87c
            ULONG JobVadsAreTracked : 1;                                      //0x87c
            ULONG VadTrackingDisabled : 1;                                    //0x87c
            ULONG AuxiliaryProcess : 1;                                       //0x87c
            ULONG SubsystemProcess : 1;                                       //0x87c
            ULONG IndirectCpuSets : 1;                                        //0x87c
            ULONG RelinquishedCommit : 1;                                     //0x87c
            ULONG HighGraphicsPriority : 1;                                   //0x87c
            ULONG CommitFailLogged : 1;                                       //0x87c
            ULONG ReserveFailLogged : 1;                                      //0x87c
            ULONG SystemProcess : 1;                                          //0x87c
            ULONG HideImageBaseAddresses : 1;                                 //0x87c
            ULONG AddressPolicyFrozen : 1;                                    //0x87c
            ULONG ProcessFirstResume : 1;                                     //0x87c
            ULONG ForegroundExternal : 1;                                     //0x87c
            ULONG ForegroundSystem : 1;                                       //0x87c
            ULONG HighMemoryPriority : 1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
            ULONG SecurityDomainChanged : 1;                                  //0x87c
            ULONG SecurityFreezeComplete : 1;                                 //0x87c
            ULONG VmProcessorHost : 1;                                        //0x87c
            ULONG VmProcessorHostTransition : 1;                              //0x87c
            ULONG AltSyscall : 1;                                             //0x87c
            ULONG TimerResolutionIgnore : 1;                                  //0x87c
            ULONG DisallowUserTerminate : 1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime : 61;                                        //0x920
    ULONGLONG LastAppState : 3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x930
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
            ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
            ULONG DisallowStrippedImages : 1;                                 //0x9d0
            ULONG ForceRelocateImages : 1;                                    //0x9d0
            ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
            ULONG StackRandomizationDisabled : 1;                             //0x9d0
            ULONG ExtensionPointDisable : 1;                                  //0x9d0
            ULONG DisableDynamicCode : 1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
            ULONG AuditDisableDynamicCode : 1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
            ULONG DisableNonSystemFonts : 1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
            ULONG PreferSystem32Images : 1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
            ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
            ULONG SignatureMitigationOptIn : 1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
            ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
            ULONG IsolateSecurityDomain : 1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x9d4
            ULONG AuditExportAddressFilter : 1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
            ULONG EnableRopStackPivot : 1;                                    //0x9d4
            ULONG AuditRopStackPivot : 1;                                     //0x9d4
            ULONG EnableRopCallerCheck : 1;                                   //0x9d4
            ULONG AuditRopCallerCheck : 1;                                    //0x9d4
            ULONG EnableRopSimExec : 1;                                       //0x9d4
            ULONG AuditRopSimExec : 1;                                        //0x9d4
            ULONG EnableImportAddressFilter : 1;                              //0x9d4
            ULONG AuditImportAddressFilter : 1;                               //0x9d4
            ULONG DisablePageCombine : 1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
            ULONG CetUserShadowStacks : 1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
            ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
            ULONG BlockNonCetBinaries : 1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
            ULONG Reserved1 : 1;                                              //0x9d4
            ULONG Reserved2 : 1;                                              //0x9d4
            ULONG Reserved3 : 1;                                              //0x9d4
            ULONG Reserved4 : 1;                                              //0x9d4
            ULONG Reserved5 : 1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
    ULONG DisabledComponentFlags;                                           //0xa20
    ULONG* volatile PathRedirectionHashes;                                  //0xa28
};