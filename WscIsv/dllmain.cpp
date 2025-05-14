#include <windows.h>
#include "SharedData.h"
#include "WscIsv.h"

#pragma comment(linker, "/section:.shared,RWS")
// 共享数据结构体
#pragma data_seg(".shared")
struct SharedParams {
	unsigned int cmd = 0;
	wchar_t displayName[MAX_PATH] = { 0 };
	unsigned int result = 0;
} g_SharedParams;
#pragma data_seg()

int GetResult() {
	return g_SharedParams.result;
}

void SetCmd(int cmd)
{
	g_SharedParams.cmd = cmd;
}

void SetDisplayName(const wchar_t* displayName)
{
	if (displayName) {
		wcscpy_s(g_SharedParams.displayName, displayName);
	}
}

DWORD WINAPI ThreadProc(LPVOID lpParam) {
	while (true)
	{
		if (g_SharedParams.cmd != 0) {
			g_SharedParams.result = WscControl(g_SharedParams.cmd, g_SharedParams.displayName);
			g_SharedParams.cmd = 0;
		}
		Sleep(1000);
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			{
				if (wcslen(g_SharedParams.displayName))
				{
					HANDLE hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
					if (hThread) {
						CloseHandle(hThread);
					}
				}
				break;
			}
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

