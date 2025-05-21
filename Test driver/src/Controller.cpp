#include <ntifs.h>

#include "Controller.h"
#include "Utils.h"

namespace Controller 
{
	NTSTATUS CreateCall(PDEVICE_OBJECT, PIRP Irp)
	{
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;
	}

	NTSTATUS CloseCall(PDEVICE_OBJECT, PIRP Irp)
	{
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;
	}

	NTSTATUS ControlCall(PDEVICE_OBJECT, PIRP Irp)
	{
		const PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
		const Request* request = (Request*)Irp->AssociatedIrp.SystemBuffer;
		const ULONG code = pStack->Parameters.DeviceIoControl.IoControlCode;
		static PEPROCESS pProcess = nullptr;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		if (pStack == nullptr || request == nullptr)
		{
			print(ERROR("Failed to get IO stack location"));
			return status;
		}

		switch (code)
		{
		case IO_ATTACH_REQUEST:
			print(INFO("IO_ATTACH_REQUEST"));
			status = PsLookupProcessByProcessId(request->hProcess, &pProcess);
			break;
		case IO_READ_REQUEST:
			print(INFO("IO_READ_REQUEST"));
			if (pProcess != nullptr)
			{
				status = MmCopyVirtualMemory(pProcess, request->TargetAddress, (PEPROCESS)PsGetCurrentProcess(), request->Buffer, request->InSize, KernelMode, request->OutSize);
			}
			break;
		case IO_WRITE_REQUEST:
			print(INFO("IO_WRITE_REQUEST"));
			if (pProcess != nullptr)
			{
				status = MmCopyVirtualMemory((PEPROCESS)PsGetCurrentProcess(), request->Buffer, pProcess, request->TargetAddress, request->InSize, KernelMode, request->OutSize);
			}
			break;
		default:
			print("Unknown IOCTL code: %llx\n", code);
			break;
		}

		if (status != STATUS_SUCCESS)
		{
			print("Failed to process IOCTL code: %llx, status: %llx\n", code, status);
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = request->OutSize;
		}
		
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;
	}
}