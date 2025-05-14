#include "WscIsv.h"
#include "SharedData.h"

HRESULT WscControl(int cmd, wchar_t* displayName)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	// 创建WSC实例
	IWscAVStatus* _IWscAVStatus = nullptr;
	hr = CoCreateInstance(CLSID_WindowsSecurityCenterISVAPI, NULL, CLSCTX_INPROC_SERVER, IID_IWscAVStatus, (PVOID*)&_IWscAVStatus);

	if (FAILED(hr)) {
		CoUninitialize();
		return hr;
	}

	// 注销命令后不需要注册
	hr = _IWscAVStatus->Unregister();
	if (cmd != CMD_REGISTER)
	{
		CoUninitialize();
		return hr;
	}

	hr = _IWscAVStatus->Register(displayName, displayName, 0, 0);
	if (SUCCEEDED(hr))
	{
		hr = _IWscAVStatus->UpdateStatus(WSC_SECURITY_PRODUCT_STATE_ON, 3);
	}
	CoUninitialize();
	return hr;
}
