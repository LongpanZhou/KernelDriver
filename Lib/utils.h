#pragma once

//LOG
#define INFO(msg)	"[*]" msg "\n"
#define OK(msg)		"[+]" msg "\n"
#define WARN(msg)	"[!]" msg "\n"
#define ERROR(msg)	"[-]" msg "\n"

//PRINT FUNC
template <typename... T>
__forceinline void print(const char* fmt, T... args)
{
    win::print_ex(0, 0, fmt, args...);
}