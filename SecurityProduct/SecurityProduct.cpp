#include <iostream>
#include <windows.h>
#include <iomanip>
#include "ProcessInject.h"
#include "../WscIsv/SharedData.h"
#include <TlHelp32.h>

/*****************************************************
 * 功能：设置控制台文本颜色
 * 参数：color - 颜色代码
 * 返回：无
 * 备注：使用Windows API设置颜色
*****************************************************/
void SetConsoleColor(int color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

/*****************************************************
 * 功能：显示居中的文本
 * 参数：text - 要显示的文本, width - 总宽度
 * 返回：无
 * 备注：在指定宽度内居中显示文本
*****************************************************/
void PrintCentered(const std::string& text, int width) {
	int padding = (width - text.length()) / 2;
	if (padding > 0) {
		std::cout << std::setw(padding) << " ";
	}
	std::cout << text << std::endl;
}

/*****************************************************
 * 功能：打个广子
 * 参数：无
 * 返回：无
 * 备注：无
 *******************************************************/
void PrintInfo()
{
	const int width = 70;

	// 程序信息
	std::string programName = "川普安全";
	std::string version = "V6.6.6";
	std::string company = "特不靠普控股有限责任股份公司";
	std::string slogan = "让Windows 防火墙关闭如此简单";

	// ===== 输出漂亮的标题框 =====
	SetConsoleColor(11); // 亮青色
	std::cout << std::string(width, '=') << std::endl;

	SetConsoleColor(14); // 亮黄色
	PrintCentered("★ " + programName + " " + version + " ★\n", width);

	SetConsoleColor(13); // 亮紫色
	PrintCentered(company, width);

	SetConsoleColor(11); // 亮青色
	std::cout << std::string(width, '=') << std::endl;
	std::cout << std::endl;

	// ===== 输出程序描述 =====
	SetConsoleColor(15); // 亮白色
	PrintCentered("【 程序简介 】", width);

	SetConsoleColor(2);
	std::cout << "  一款功能强大、界面友好的低调工具，为用户提供高效稳定的防火墙操作体验。" << std::endl;
	std::cout << std::endl;

	// ===== 输出功能特点 =====
	SetConsoleColor(15); // 亮白色
	PrintCentered("【 主要功能 】", width);

	SetConsoleColor(10); // 亮绿色
	std::cout << "  √ 关闭Windows 防火墙" << std::endl;
	std::cout << "  √ 打开Windows 防火墙" << std::endl;
	std::cout << "  √ 停止Windows 防火墙" << std::endl;
	std::cout << "  √ 开启Windows 防火墙" << std::endl;
	std::cout << "  √ 关闭 打开 停止 开启 Windows 防火墙" << std::endl;
	std::cout << std::endl;

	// ===== 输出广告语 =====
	SetConsoleColor(14); // 亮黄色
	std::cout << std::string(width, '-') << std::endl;
	PrintCentered("★ " + slogan + " ★", width);
	std::cout << std::string(width, '-') << std::endl;
	std::cout << std::endl;

	// ===== 输出联系信息 =====
	SetConsoleColor(10);
	PrintCentered("【 联系方式 】", width);

	SetConsoleColor(14);

	std::cout << "  By：FengTeng" << std::endl;
	std::cout << "  QQ：525293680" << std::endl;

	std::cout << std::endl;

	SetConsoleColor(13); // 亮紫色
	PrintCentered("感谢您选择我们的产品！\n", width);

	SetConsoleColor(9);
}

/*****************************************************
 * 功能：杀死任务管理器进程
 * 参数：无
 * 返回：无
 * 备注：使用Windows API遍历进程列表，杀死任务管理器进程
 *******************************************************/
void KillTaskManagerProcesses()
{
	// 获取进程快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "创建进程快照失败，错误代码：" << GetLastError() << std::endl;
		return;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	// 遍历进程列表
	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, L"taskmgr.exe") == 0) {
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
				if (hProcess != NULL) {
					TerminateProcess(hProcess, 0);
					CloseHandle(hProcess);
				}
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
}

int main()
{
	PrintInfo();

	KillTaskManagerProcesses();

	// 先获取系统目录
	wchar_t taskmgrPath[MAX_PATH];
	GetSystemDirectoryW(taskmgrPath, MAX_PATH);
	// Taskmgr.exe
	wcscat_s(taskmgrPath, L"\\Taskmgr.exe");

	/**
	* 关键设置 1 设置显示名称
	*/
	const wchar_t* DisplayName = L"川普安全";
	SetDisplayName(DisplayName);

	// 创建一个新的进程
	ProcessInjector injector;

	do
	{
		if (!injector.CreateProcess(taskmgrPath, L"", true)) {
			std::cerr << "创建进程失败，错误代码：" << injector.GetLastError() << std::endl;
			break;
		}
		// 先获取当前程序的运行目录
		wchar_t DllPath[MAX_PATH];
		GetModuleFileNameW(NULL, DllPath, MAX_PATH);
		// 移除文件名
		wchar_t* lastSlash = wcsrchr(DllPath, L'\\');
		if (lastSlash) {
			*lastSlash = L'\0';
		}
		wcscat_s(DllPath, L"\\WscIsv.dll");
		// 注入DLL
		if (!injector.InjectDll(DllPath)) {
			std::cerr << "注入DLL失败，错误代码：" << injector.GetLastError() << std::endl;
			break;
		}

		/**
		* 关键设置 2 命令
		*/
		// 注册命令
		SetCmd(CMD_REGISTER);

		PrintCentered("Windows 防火墙已关闭!\n", 70);

		PrintCentered("任意键卸载安全软件\n", 70);

		system("pause");

		// 卸载命令
		SetCmd(CMD_UNREGISTER);

		PrintCentered("川普安全已卸载", 70);

		Sleep(1500);

	} while (0);

	system("pause");
}
