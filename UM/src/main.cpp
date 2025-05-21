#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "Utils.h"

static DWORD get_process_id(const wchar_t* process_name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, process_name) == 0) {
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return 0;
}

bool attach_to_process(HANDLE driver_handle, DWORD pid)
{
	Request r;
	r.hProcess = (HANDLE)pid;
	return DeviceIoControl(driver_handle, IO_ATTACH_REQUEST, &r, sizeof(r), nullptr, 0, nullptr, nullptr);
}

template <class T>
T read_memory(HANDLE driver_handle, void* address)
{
	T temp;

	Request r;
	r.TargetAddress = address;
	r.Buffer = &temp;
	r.InSize = sizeof(T);

	DeviceIoControl(driver_handle, IO_READ_REQUEST, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	return temp;
}

template <class T>
T write_memory(HANDLE driver_handle, void* address, T value)
{
	Request r;
	r.TargetAddress = address;
	r.Buffer = &value;
	r.InSize = sizeof(T);
	DeviceIoControl(driver_handle, IO_WRITE_REQUEST, &r, sizeof(r), nullptr, 0, nullptr, nullptr);
	return value;
}

void main()
{
	SetConsoleTitleA("Usermode Driver Example");

	HANDLE hDriver = CreateFileA("\\\\.\\CCP-DRV", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open driver handle\n");
		system("pause");
		return;
	}
	
	DWORD pid = get_process_id(L"notepad.exe");
	if (pid == 0) {
		printf("[-] Failed to find process\n");
		CloseHandle(hDriver);
		system("pause");
		return;
	}
	
	if (attach_to_process(hDriver, pid) == false) {
		printf("[-] Failed to attach to process\n");
		CloseHandle(hDriver);
		system("pause");
		return;
	}

	printf("[+] Found process ID: %d\n", pid);
	CloseHandle(hDriver);
	system("pause");
	return;
}