#include "Controller.h"
#include "Utils.h"
#include "Structs.h"
#include "ia32.h"

#include <intrin.h>

//namespace
using namespace Controller;

//Define
#define PMASK 0x000F'FFFF'FFFF'F000

//GLOBAL VARIABLES
UNICODE_STRING DriverName, SymbolName;

//FUNCTION PROTOTYPES
BOOLEAN UnmapVirtualToPhysical(PVOID TargetAddress);
PVOID MapPhysicalToVirtual(PVOID TargetAddress);
PVOID GetPhysicalAddress(PVOID VirtualAddress, CR3 cr3);
BOOLEAN ReadVirtualMemory(PVOID TargetAddress, PVOID pBuffer, SIZE_T size, CR3 cr3);
PVOID EnumerateModuleBaseAddress(PEPROCESS pProcess, const wchar_t* ModuleName);
PEPROCESS EnumerateProcess(const char* ProcessName);

void Unload(PDRIVER_OBJECT)
{
	//__try
	//{
	//	IoDeleteDevice(pDriverObject->DeviceObject);

	//	if (IoDeleteSymbolicLink(&SymbolName) != STATUS_SUCCESS)
	//	{
	//		print(ERROR("Failed to delete symbolic link"));
	//	}

	//	print(INFO("DRIVER UNLOADED"));
	//}
	//__except (EXCEPTION_EXECUTE_HANDLER)
	//{
	//	print(ERROR("Exception occurred during driver unload"));
	//	print(ERROR("Error code: %x"), GetExceptionCode());
	//}
}

NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING
)
{
	//Redirect functions
	DriverObject->DriverUnload = Unload;
	//DriverObject->MajorFunction[IRP_MJ_CREATE] = Controller::CreateCall;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE] = Controller::CloseCall;
	//DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Controller::ControlCall;

	////Register Symbolic Link
	//PDEVICE_OBJECT pDeviceObj;
	//RtlInitUnicodeString(&DriverName, L"\\Device\\CCP-DRV");
	//RtlInitUnicodeString(&SymbolName, L"\\DosDevices\\CCP-DRV");

	//if (IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObj) != STATUS_SUCCESS)
	//{
	//	print(ERROR("Failed to create device"));
	//	return STATUS_UNSUCCESSFUL;
	//}

	//if (IoCreateSymbolicLink(&SymbolName, &DriverName) != STATUS_SUCCESS)
	//{
	//	print(ERROR("Failed to create symbolic link"));
	//	return STATUS_UNSUCCESSFUL;
	//}

	//pDeviceObj->Flags |= DO_BUFFERED_IO;
	//pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

	//Main code here
	__try
	{
		PEPROCESS pCurrentProcess = EnumerateProcess("notepad.exe");		
		PVOID pModuleBaseeAddress = EnumerateModuleBaseAddress(pCurrentProcess, L"HAHAHAHA");
		print(INFO("Module Base Address: %p"), pModuleBaseeAddress);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		print(ERROR("Exception occurred during driver entry"));
		//Unload(DriverObject);
		return STATUS_UNSUCCESSFUL;
	}
}

BOOLEAN UnmapPhysicalMemory(PVOID TargetAddress)
{
	__try
	{
		print(INFO("--------------UnmapPhysicalMemory-----------------"));

		__try
		{
			VirtualAddress VA = { .Value = (ULONG64)TargetAddress };
			CR3 cr3 = { .AsUInt = __readcr3() };
			auto PML4E = ((PML4E_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(cr3.AddressOfPageDirectory << 12) }))[VA.P4_IDX];
			auto PDPE = ((PDPTE_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(PML4E.PageFrameNumber << 12) }))[VA.P3_IDX];
			auto PDE = ((PDE_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(PDPE.PageFrameNumber << 12) }))[VA.P2_IDX];
			auto& PT = ((PTE_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(PDE.PageFrameNumber << 12) }))[VA.P1_IDX];

			PT.Present = 0;
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			print(ERROR("Exception occurred while unmapping physical memory"));
			return false;
		}
	}
	__finally
	{
		print(INFO("--------------UnmapPhysicalMemory-----------------"));
	}
}

PVOID MapPhysicalToVirtual(PVOID TargetAddress)
{
	__try
	{
		print(INFO("--------------MapPhysicalToVirtual-----------------"));

		__try
		{
			CR3 cr3 = { .AsUInt = __readcr3() };
			constexpr int PML4E_IDX = 0;
			print(INFO("Target Address: %p"), TargetAddress);
			print(INFO("CR3: %p"), cr3.AsUInt);

			auto PML4E = ((PML4E_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(cr3.AddressOfPageDirectory << 12) }))[PML4E_IDX];
			print(INFO("PML4E: %p"), PML4E.PageFrameNumber << 12);

			for (int PDPE_IDX = 0; PDPE_IDX < 512; PDPE_IDX++)
			{
				auto PDPE = ((PDPTE_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(PML4E.PageFrameNumber << 12) }))[PDPE_IDX];
				if (!PDPE.Present)
					continue;

				print(INFO("PDPE: %p"), PDPE.PageFrameNumber << 12);

				for (int PDE_IDX = 0; PDE_IDX < 512; PDE_IDX++)
				{
					auto PDE = ((PDE_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(PDPE.PageFrameNumber << 12) }))[PDE_IDX];
					
					if (!PDE.Present)
						continue;

					print(INFO("PDE: %p"), PDE.PageFrameNumber << 12);

					for (int PT_IDX = 0; PT_IDX < 512; PT_IDX++)
					{
						auto& PTE = ((PTE_64*)MmGetVirtualForPhysical({ .QuadPart = (LONG64)(PDE.PageFrameNumber << 12) }))[PT_IDX];

						if (PTE.Present)
							continue;

						print(INFO("PT: %p"), PTE.PageFrameNumber << 12);

						PTE.Present = 1;
						PTE.Write = 1;
						PTE.PageFrameNumber = (ULONG64)TargetAddress >> 12;

						VirtualAddress VA = {};
						VA.Physical_Page_Offset = (ULONG64)TargetAddress & 0xFFF;
						VA.P1_IDX = PT_IDX;
						VA.P2_IDX = PDE_IDX;
						VA.P3_IDX = PDPE_IDX;
						VA.P4_IDX = PML4E_IDX;

						print(INFO("VA: %p"), VA.Value);
						return (PVOID)VA.Value;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			print(ERROR("Exception occurred while mapping physical to virtual address"));
		}
	}
	__finally
	{
		print(INFO("--------------MapPhysicalToVirtual-----------------"));
	}
	return nullptr;
}

PVOID GetPhysicalAddress(PVOID TargetAddress, CR3 cr3) {
	print(INFO("--------------GetPhysicalAddress-----------------"));
	PVOID mappedPML4E_VA = nullptr;
	PVOID mappedPDPE_VA = nullptr;
	PVOID mappedPDE_VA = nullptr;
	PVOID mappedPTE_VA = nullptr;

	__try
	{
		__try
		{
			VirtualAddress VA = { .Value = (ULONG64)TargetAddress };

			mappedPML4E_VA = MapPhysicalToVirtual((PVOID)(cr3.AddressOfPageDirectory << 12));
			if (!mappedPML4E_VA) return nullptr;
			auto PML4E = ((PML4E_64*)mappedPML4E_VA)[VA.P4_IDX];

			mappedPDPE_VA = MapPhysicalToVirtual((PVOID)(PML4E.PageFrameNumber << 12));
			if (!mappedPDPE_VA) return nullptr;
			auto PDPE = ((PDPTE_64*)mappedPDPE_VA)[VA.P3_IDX];

			mappedPDE_VA = MapPhysicalToVirtual((PVOID)(PDPE.PageFrameNumber << 12));
			if (!mappedPDE_VA) return nullptr;
			auto PDE = ((PDE_64*)mappedPDE_VA)[VA.P2_IDX];

			mappedPTE_VA = MapPhysicalToVirtual((PVOID)(PDE.PageFrameNumber << 12));
			if (!mappedPTE_VA) return nullptr;
			auto PT = ((PTE_64*)mappedPTE_VA)[VA.P1_IDX];

			PVOID PA = (PVOID)((PT.PageFrameNumber << 12) | VA.Physical_Page_Offset);

			return PA;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			print(ERROR("Exception occurred while getting physical address"));
			return nullptr;
		}
	}
	__finally
	{
		// Unmap in reverse order
		if (mappedPTE_VA) UnmapPhysicalMemory(mappedPTE_VA);
		if (mappedPDE_VA) UnmapPhysicalMemory(mappedPDE_VA);
		if (mappedPDPE_VA) UnmapPhysicalMemory(mappedPDPE_VA);
		if (mappedPML4E_VA) UnmapPhysicalMemory(mappedPML4E_VA);
		print(INFO("--------------GetPhysicalAddress-----------------"));
	}
}

BOOLEAN ReadVirtualMemory(PVOID TargetAddress, PVOID pBuffer, SIZE_T size, CR3 cr3)
{
	__try
	{
		PVOID PhysicalAddress = GetPhysicalAddress(TargetAddress, cr3);
		PVOID VirtualAddress = MapPhysicalToVirtual(PhysicalAddress);
		memcpy(pBuffer, VirtualAddress, size);
		UnmapPhysicalMemory(VirtualAddress);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		print(ERROR("Exception occurred while reading virtual memory"));
		return false;
	}
}

PVOID EnumerateModuleBaseAddress(PEPROCESS pProcess, const wchar_t* ModuleName)
{
	__try
	{
		print(INFO("--------------EnumerateModuleBaseAddress-----------------"));
		
		__try
		{
			if (pProcess == nullptr)
			{
				print(ERROR("Failed to get process"));
				return nullptr;
			}
			PKPROCESS pKProcess = (PKPROCESS)CONTAINING_RECORD(pProcess, _EPROCESS, Pcb);
			CR3 cr3 = { .AsUInt = pKProcess->DirectoryTableBase };
			print(INFO("Target Module Name: %ws"), ModuleName);

			PPEB pPeb = pProcess->Peb;
			if (pPeb == nullptr)
			{
				print(ERROR("Failed to get PEB"));
				return nullptr;
			}

			_PEB PEB;
			ReadVirtualMemory(pPeb, &PEB, sizeof(_PEB), cr3);

			_PEB_LDR_DATA* pLdr = PEB.Ldr;
			_PEB_LDR_DATA ldr;
			ReadVirtualMemory(pLdr, &ldr, sizeof(_PEB_LDR_DATA), cr3);

			wchar_t pBuffer[256];
			_LDR_DATA_TABLE_ENTRY LdrEntry;
			PLIST_ENTRY pHead = ldr.InLoadOrderModuleList.Flink;
			PLIST_ENTRY pCurrent = ldr.InLoadOrderModuleList.Flink;

			do
			{
				if (!ReadVirtualMemory(pCurrent, &LdrEntry, sizeof(_LDR_DATA_TABLE_ENTRY), cr3))
					break;

				pCurrent = LdrEntry.InLoadOrderLinks.Flink;

				if (LdrEntry.DllBase && LdrEntry.BaseDllName.Buffer && LdrEntry.BaseDllName.Length > 0) {
					SIZE_T read_size = min(sizeof(pBuffer) - sizeof(wchar_t), (SIZE_T)LdrEntry.BaseDllName.Length);

					if (ReadVirtualMemory(LdrEntry.BaseDllName.Buffer, pBuffer, read_size, cr3))
					{
						pBuffer[read_size / sizeof(wchar_t)] = L'\0';
						print(INFO("Module Name: %ws"), pBuffer);

						if(!wcscmp(pBuffer, ModuleName))
						{
							print(INFO("Module Base Address: %p"), LdrEntry.DllBase);
							return GetPhysicalAddress(LdrEntry.DllBase, cr3);
						}
					}
				}
			} while (pCurrent != pHead);

			return nullptr;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			print(ERROR("Exception occurred while enumerating module base address"));
			return nullptr;
		}
	}
	__finally
	{
		print(INFO("--------------EnumerateModuleBaseAddress-----------------"));
	}
}

PEPROCESS EnumerateProcess(const char* ProcessName)
{
	__try
	{
		print(INFO("--------------EnumerateProcess-----------------"));
		
		__try
		{
			PEPROCESS pProcHead = PsInitialSystemProcess;

			if (pProcHead == nullptr)
			{
				print(ERROR("Failed to get process list head"));
				return nullptr;
			}

			PLIST_ENTRY pHead = &PsInitialSystemProcess->ActiveProcessLinks;
			PLIST_ENTRY pCurrent = pHead->Flink;

			while (pCurrent != pHead)
			{
				PEPROCESS pProcess = CONTAINING_RECORD(pCurrent, _EPROCESS, ActiveProcessLinks);
				print(INFO("Process Name: %s"), pProcess->ImageFileName);
				print(INFO("Process ID: %u"), pProcess->UniqueProcessId);
				pCurrent = pCurrent->Flink;

				if (!strcmp((char*)pProcess->ImageFileName, ProcessName))
					return pProcess;
			}

			return nullptr;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			print(ERROR("Exception occurred while enumerating process"));
			return nullptr;
		}
	}
	__finally
	{
		print(INFO("--------------EnumerateProcess-----------------"));
	}
}