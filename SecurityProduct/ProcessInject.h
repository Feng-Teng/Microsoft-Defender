/**
 * @file ProcessInject.h
 * @brief ���̴�����DLLע����غ�������
 * @author YueLuBingYour
 * @date 2025-05-13
 */

#ifndef PROCESS_INJECT_H_
#define PROCESS_INJECT_H_

#include <Windows.h>
#include <string>

 /**
  * @brief ���̴�����DLLע����ع�����
  */
class ProcessInjector {
public:
    ProcessInjector();
    ~ProcessInjector();

    /**
     * @brief ����һ���½���
     * @param applicationPath Ӧ�ó���·��
     * @param commandLine �����в���
     * @param createSuspended �Ƿ��Թ���ʽ����
     * @return �ɹ�����true��ʧ�ܷ���false
     */
    bool CreateProcess(const std::wstring& applicationPath,
                       const std::wstring& commandLine = L"",
                       bool createSuspended = false);

    /**
     * @brief ��ǰ�������ӽ���ע��DLL
     * @param dllPath DLL�ļ�·��
     * @return �ɹ�����true��ʧ�ܷ���false
     */
    bool InjectDll(const std::wstring& dllPath);

    /**
     * @brief ��ȡ���һ�δ������
     * @return Windows�������
     */
    DWORD GetLastError() const;

    /**
     * @brief ��ȡ�����Ľ���ID
     * @return ����ID
     */
    DWORD GetProcessId() const;

    /**
     * @brief ��ȡ���̾��
     * @return ���̾��
     */
    HANDLE GetProcessHandle() const;

    /**
     * @brief �ָ�����Ľ���
     * @return �ɹ�����true��ʧ�ܷ���false
     */
    bool ResumeProcess();

    /**
     * @brief ʹ��CreateRemoteThread������ָ������ע��DLL����̬������
     * @param processId Ŀ�����ID
     * @param dllPath DLL�ļ�·��
     * @param lastError [���] ���ʧ�ܣ������������
     * @return �ɹ�����true��ʧ�ܷ���false
     */
    static bool InjectDllToProcess(DWORD processId, const std::wstring& dllPath, DWORD& lastError);

private:
    PROCESS_INFORMATION process_info_;
    DWORD last_error_;
    bool owns_handles_;
};

#endif // PROCESS_INJECT_H_