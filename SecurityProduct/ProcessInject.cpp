#include "ProcessInject.h"
#include <TlHelp32.h>
#include <vector>

ProcessInjector::ProcessInjector() : last_error_(0), owns_handles_(false) {
    ZeroMemory(&process_info_, sizeof(PROCESS_INFORMATION));
}

ProcessInjector::~ProcessInjector() {
    if (owns_handles_) {
        if (process_info_.hProcess) {
			TerminateProcess(process_info_.hProcess, 0);
            CloseHandle(process_info_.hProcess);
            process_info_.hProcess = NULL;
        }
        if (process_info_.hThread) {
            CloseHandle(process_info_.hThread);
            process_info_.hThread = NULL;
        }
    }
}

/*****************************************************
 * 功能：创建一个新的目标进程
 * 参数：applicationPath - 应用程序完整路径
 *       commandLine - 命令行参数
 *       createSuspended - 是否以挂起状态创建进程
 * 返回：成功返回true，失败返回false
 * 备注：如果createSuspended为true，进程会以挂起状态创建，
 *       需要调用ResumeProcess恢复执行
*****************************************************/
bool ProcessInjector::CreateProcess(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    bool createSuspended) {

    // 如果已有进程，先清理句柄
    if (owns_handles_) {
        if (process_info_.hProcess) {
            CloseHandle(process_info_.hProcess);
            process_info_.hProcess = NULL;
        }
        if (process_info_.hThread) {
            CloseHandle(process_info_.hThread);
            process_info_.hThread = NULL;
        }
    }

    STARTUPINFOW startup_info = { 0 };
    startup_info.cb = sizeof(STARTUPINFOW);

    // 准备命令行参数
    std::wstring mutable_command_line;
    if (!commandLine.empty()) {
        mutable_command_line = applicationPath + L" " + commandLine;
    }
    else {
        mutable_command_line = applicationPath;
    }

    std::vector<wchar_t> command_line_buffer(mutable_command_line.begin(), mutable_command_line.end());
    command_line_buffer.push_back(L'\0');  // 确保字符串以null结尾

    DWORD creation_flags = 0;
    if (createSuspended) {
        creation_flags |= CREATE_SUSPENDED;
    }

    // 创建进程
    if (!::CreateProcessW(
        NULL,                          // 应用程序名称
        command_line_buffer.data(),    // 命令行
        NULL,                          // 进程安全属性
        NULL,                          // 线程安全属性
        FALSE,                         // 不继承句柄
        creation_flags,                // 创建标志
        NULL,                          // 环境块
        NULL,                          // 当前目录
        &startup_info,                 // 启动信息
        &process_info_                 // 进程信息
        )) {
        last_error_ = ::GetLastError();
        return false;
    }

    owns_handles_ = true;
    return true;
}

/*****************************************************
 * 功能：向当前创建的子进程注入DLL
 * 参数：dllPath - 要注入的DLL路径
 * 返回：成功返回true，失败返回false
 * 备注：必须先成功调用CreateProcess
*****************************************************/
bool ProcessInjector::InjectDll(const std::wstring& dllPath) {
    if (!process_info_.hProcess) {
        last_error_ = ERROR_INVALID_HANDLE;
        return false;
    }

    // 调用静态方法执行注入
    if (!InjectDllToProcess(process_info_.dwProcessId, dllPath, last_error_)) {
        return false;
    }

    return true;
}

/*****************************************************
 * 功能：恢复挂起的进程执行
 * 参数：无
 * 返回：成功返回true，失败返回false
 * 备注：用于恢复以挂起方式创建的进程
*****************************************************/
bool ProcessInjector::ResumeProcess() {
    if (!process_info_.hThread) {
        last_error_ = ERROR_INVALID_HANDLE;
        return false;
    }

    DWORD result = ResumeThread(process_info_.hThread);
    if (result == (DWORD)-1) {
        last_error_ = ::GetLastError();
        return false;
    }

    return true;
}

/*****************************************************
 * 功能：获取最近一次错误代码
 * 参数：无
 * 返回：Windows错误代码
 * 备注：无
*****************************************************/
DWORD ProcessInjector::GetLastError() const {
    return last_error_;
}

/*****************************************************
 * 功能：获取创建的进程ID
 * 参数：无
 * 返回：进程ID
 * 备注：如果进程未创建，返回0
*****************************************************/
DWORD ProcessInjector::GetProcessId() const {
    return process_info_.dwProcessId;
}

/*****************************************************
 * 功能：获取进程句柄
 * 参数：无
 * 返回：进程句柄
 * 备注：无
*****************************************************/
HANDLE ProcessInjector::GetProcessHandle() const {
    return process_info_.hProcess;
}

/*****************************************************
 * 功能：使用CreateRemoteThread方法向指定进程注入DLL（静态方法）
 * 参数：processId - 目标进程ID
 *       dllPath - 要注入的DLL路径
 *       lastError - [输出] 如果失败，包含错误代码
 * 返回：成功返回true，失败返回false
 * 备注：此方法通过在远程进程中创建线程并执行LoadLibrary来注入DLL
*****************************************************/
bool ProcessInjector::InjectDllToProcess(DWORD processId, const std::wstring& dllPath, DWORD& lastError) {
    HANDLE process_handle = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processId);

    if (process_handle == NULL) {
        lastError = ::GetLastError();
        return false;
    }

    // 在远程进程中分配内存
    size_t dll_path_size = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remote_memory = VirtualAllocEx(
        process_handle,
        NULL,
        dll_path_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (remote_memory == NULL) {
        lastError = ::GetLastError();
        CloseHandle(process_handle);
        return false;
    }

    // 将DLL路径写入远程进程内存
    if (!WriteProcessMemory(
        process_handle,
        remote_memory,
        dllPath.c_str(),
        dll_path_size,
        NULL)) {
        lastError = ::GetLastError();
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }

    // 获取LoadLibraryW的地址
    HMODULE kernel32_module = GetModuleHandleW(L"kernel32.dll");
    if (kernel32_module == NULL) {
        lastError = ::GetLastError();
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }

    FARPROC load_library_address = GetProcAddress(kernel32_module, "LoadLibraryW");
    if (load_library_address == NULL) {
        lastError = ::GetLastError();
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }

    // 创建远程线程执行LoadLibraryW
    HANDLE remote_thread = CreateRemoteThread(
        process_handle,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)load_library_address,
        remote_memory,
        0,
        NULL);

    if (remote_thread == NULL) {
        lastError = ::GetLastError();
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }

    // 等待远程线程执行完成
    WaitForSingleObject(remote_thread, INFINITE);

    // 获取线程退出码，检查DLL是否成功加载
    DWORD exit_code = 0;
    GetExitCodeThread(remote_thread, &exit_code);

    // 清理资源
    CloseHandle(remote_thread);
    VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
    CloseHandle(process_handle);

    if (exit_code == 0) {
        lastError = ERROR_MOD_NOT_FOUND;  // 使用标准错误代码表示DLL加载失败
        return false;
    }

    return true;
}