#pragma once
#include <Windows.h>

// CMD命令
#define CMD_REGISTER 0x1
#define CMD_UNREGISTER 0x2

// 导出函数声明
#ifdef WSCISV_EXPORTS
#define DLL_API extern "C" __declspec(dllexport)
#else
#define DLL_API extern "C" __declspec(dllimport)
#endif

DLL_API int GetResult();

DLL_API void SetCmd(int cmd);

DLL_API void SetDisplayName(const wchar_t* displayName);

