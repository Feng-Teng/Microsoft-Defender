/**
 * @file ProcessInject.h
 * @brief 进程创建与DLL注入相关函数声明
 * @author YueLuBingYour
 * @date 2025-05-13
 */

#ifndef PROCESS_INJECT_H_
#define PROCESS_INJECT_H_

#include <Windows.h>
#include <string>

 /**
  * @brief 进程创建与DLL注入相关功能类
  */
class ProcessInjector {
public:
    ProcessInjector();
    ~ProcessInjector();

    /**
     * @brief 创建一个新进程
     * @param applicationPath 应用程序路径
     * @param commandLine 命令行参数
     * @param createSuspended 是否以挂起方式创建
     * @return 成功返回true，失败返回false
     */
    bool CreateProcess(const std::wstring& applicationPath,
                       const std::wstring& commandLine = L"",
                       bool createSuspended = false);

    /**
     * @brief 向当前创建的子进程注入DLL
     * @param dllPath DLL文件路径
     * @return 成功返回true，失败返回false
     */
    bool InjectDll(const std::wstring& dllPath);

    /**
     * @brief 获取最近一次错误代码
     * @return Windows错误代码
     */
    DWORD GetLastError() const;

    /**
     * @brief 获取创建的进程ID
     * @return 进程ID
     */
    DWORD GetProcessId() const;

    /**
     * @brief 获取进程句柄
     * @return 进程句柄
     */
    HANDLE GetProcessHandle() const;

    /**
     * @brief 恢复挂起的进程
     * @return 成功返回true，失败返回false
     */
    bool ResumeProcess();

    /**
     * @brief 使用CreateRemoteThread方法向指定进程注入DLL（静态方法）
     * @param processId 目标进程ID
     * @param dllPath DLL文件路径
     * @param lastError [输出] 如果失败，包含错误代码
     * @return 成功返回true，失败返回false
     */
    static bool InjectDllToProcess(DWORD processId, const std::wstring& dllPath, DWORD& lastError);

private:
    PROCESS_INFORMATION process_info_;
    DWORD last_error_;
    bool owns_handles_;
};

#endif // PROCESS_INJECT_H_