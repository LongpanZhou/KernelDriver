#include <iostream>
#include <cstdint>
#include <windows.h>

typedef NTSTATUS(WINAPI* NtUserQueryDisplay_t)(uint64_t param);

int main()
{
    HMODULE Win32u = LoadLibraryA("win32u.dll");
    if (!Win32u) return NULL;

    auto NtUserQueryDisplay = (NtUserQueryDisplay_t)GetProcAddress(Win32u, "NtUserQueryDisplay");
    if (!NtUserQueryDisplay) return NULL;

    NTSTATUS status = NtUserQueryDisplay(0);
    std::cout << "NtUserQueryDisplay returned " << status << std::endl;
    return NULL;
}