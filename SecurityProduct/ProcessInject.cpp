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
 * ���ܣ�����һ���µ�Ŀ�����
 * ������applicationPath - Ӧ�ó�������·��
 *       commandLine - �����в���
 *       createSuspended - �Ƿ��Թ���״̬��������
 * ���أ��ɹ�����true��ʧ�ܷ���false
 * ��ע�����createSuspendedΪtrue�����̻��Թ���״̬������
 *       ��Ҫ����ResumeProcess�ָ�ִ��
*****************************************************/
bool ProcessInjector::CreateProcess(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    bool createSuspended) {

    // ������н��̣���������
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

    // ׼�������в���
    std::wstring mutable_command_line;
    if (!commandLine.empty()) {
        mutable_command_line = applicationPath + L" " + commandLine;
    }
    else {
        mutable_command_line = applicationPath;
    }

    std::vector<wchar_t> command_line_buffer(mutable_command_line.begin(), mutable_command_line.end());
    command_line_buffer.push_back(L'\0');  // ȷ���ַ�����null��β

    DWORD creation_flags = 0;
    if (createSuspended) {
        creation_flags |= CREATE_SUSPENDED;
    }

    // ��������
    if (!::CreateProcessW(
        NULL,                          // Ӧ�ó�������
        command_line_buffer.data(),    // ������
        NULL,                          // ���̰�ȫ����
        NULL,                          // �̰߳�ȫ����
        FALSE,                         // ���̳о��
        creation_flags,                // ������־
        NULL,                          // ������
        NULL,                          // ��ǰĿ¼
        &startup_info,                 // ������Ϣ
        &process_info_                 // ������Ϣ
        )) {
        last_error_ = ::GetLastError();
        return false;
    }

    owns_handles_ = true;
    return true;
}

/*****************************************************
 * ���ܣ���ǰ�������ӽ���ע��DLL
 * ������dllPath - Ҫע���DLL·��
 * ���أ��ɹ�����true��ʧ�ܷ���false
 * ��ע�������ȳɹ�����CreateProcess
*****************************************************/
bool ProcessInjector::InjectDll(const std::wstring& dllPath) {
    if (!process_info_.hProcess) {
        last_error_ = ERROR_INVALID_HANDLE;
        return false;
    }

    // ���þ�̬����ִ��ע��
    if (!InjectDllToProcess(process_info_.dwProcessId, dllPath, last_error_)) {
        return false;
    }

    return true;
}

/*****************************************************
 * ���ܣ��ָ�����Ľ���ִ��
 * ��������
 * ���أ��ɹ�����true��ʧ�ܷ���false
 * ��ע�����ڻָ��Թ���ʽ�����Ľ���
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
 * ���ܣ���ȡ���һ�δ������
 * ��������
 * ���أ�Windows�������
 * ��ע����
*****************************************************/
DWORD ProcessInjector::GetLastError() const {
    return last_error_;
}

/*****************************************************
 * ���ܣ���ȡ�����Ľ���ID
 * ��������
 * ���أ�����ID
 * ��ע���������δ����������0
*****************************************************/
DWORD ProcessInjector::GetProcessId() const {
    return process_info_.dwProcessId;
}

/*****************************************************
 * ���ܣ���ȡ���̾��
 * ��������
 * ���أ����̾��
 * ��ע����
*****************************************************/
HANDLE ProcessInjector::GetProcessHandle() const {
    return process_info_.hProcess;
}

/*****************************************************
 * ���ܣ�ʹ��CreateRemoteThread������ָ������ע��DLL����̬������
 * ������processId - Ŀ�����ID
 *       dllPath - Ҫע���DLL·��
 *       lastError - [���] ���ʧ�ܣ������������
 * ���أ��ɹ�����true��ʧ�ܷ���false
 * ��ע���˷���ͨ����Զ�̽����д����̲߳�ִ��LoadLibrary��ע��DLL
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

    // ��Զ�̽����з����ڴ�
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

    // ��DLL·��д��Զ�̽����ڴ�
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

    // ��ȡLoadLibraryW�ĵ�ַ
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

    // ����Զ���߳�ִ��LoadLibraryW
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

    // �ȴ�Զ���߳�ִ�����
    WaitForSingleObject(remote_thread, INFINITE);

    // ��ȡ�߳��˳��룬���DLL�Ƿ�ɹ�����
    DWORD exit_code = 0;
    GetExitCodeThread(remote_thread, &exit_code);

    // ������Դ
    CloseHandle(remote_thread);
    VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
    CloseHandle(process_handle);

    if (exit_code == 0) {
        lastError = ERROR_MOD_NOT_FOUND;  // ʹ�ñ�׼��������ʾDLL����ʧ��
        return false;
    }

    return true;
}