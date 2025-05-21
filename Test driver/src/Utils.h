#pragma once

//LOG
#define INFO(msg)	"[*]" msg "\n"
#define OK(msg)		"[+]" msg "\n"
#define WARN(msg)	"[!]" msg "\n"
#define ERROR(msg)	"[-]" msg "\n"

//PRINT FUNC
template <typename... T>
inline void print(const char* fmt, T... args)
{
	DbgPrintEx(0, 0, fmt, args...);
}

//UNDOCUMENTED ILLGEL FUNCS
extern "C"
{
	NTKERNELAPI NTSTATUS IoCreateDriver
	(
		PUNICODE_STRING DriverName,
		PDRIVER_INITIALIZE InitializationFunction
	);
	
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory
	(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		SIZE_T ReturnSize
	);
}