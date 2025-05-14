#pragma once
#include <Windows.h>
#include <iwscapi.h>

CONST GUID CLSID_WindowsSecurityCenterISVAPI = { 0x0f2102c37, 0x90c3, 0x450c, {0x0b3, 0x0f6, 0x92, 0x0be, 0x16, 0x93, 0x0bd, 0x0f2} };
CONST GUID IID_IWscASStatus = { 0x024e9756, 0xba6c, 0x4ad1, {0x83, 0x21, 0x87, 0xba, 0xe7, 0x8f, 0xd0, 0xe3} };
CONST GUID IID_IWscFWStatus = { 0x9b8f6c6e, 0x8a4a, 0x4891, {0xaf, 0x63, 0x1a, 0x2f, 0x50, 0x92, 0x40, 0x40} };
CONST GUID IID_IWscFWStatus2 = { 0x62f698cb, 0x094a, 0x4c68, {0x94, 0x19, 0x8e, 0x8c, 0x49, 0x42, 0x0e, 0x59} };
CONST GUID IID_IWscAVStatus = { 0x3901a765, 0x0ab91, 0x4ba9, {0xa5, 0x53, 0x5b, 0x85, 0x38, 0xde, 0xb8, 0x40} };
CONST GUID IID_IWscAVStatus2 = { 0x206d9c96, 0xacdf, 0x484b, {0x83, 0x3e, 0xde, 0xb9, 0x14, 0x56, 0x5e, 0x44} };
CONST GUID IID_IWscAVStatus3 = { 0xcf007ca2, 0xf5e3, 0x11e5, {0x9c, 0xe9, 0x5e, 0x55, 0x17, 0x50, 0x7c, 0x66} };
CONST GUID IID_IWscAVStatus4 = { 0x4dcbafac, 0x29ba, 0x46b1, {0x80, 0xfc, 0xb8, 0xbd, 0xe3, 0xc0, 0xae, 0x4d} };

class IWscFWStatus2 {
private:
	virtual HRESULT QueryInterface() = 0;
	virtual HRESULT AddRef() = 0;
	virtual HRESULT Release() = 0;

public:
	virtual HRESULT Register(wchar_t*, wchar_t*, int, int) = 0;
	virtual HRESULT Unregister(void) = 0;
	virtual HRESULT UpdateStatus(WSC_SECURITY_PRODUCT_STATE) = 0;
};

class IWscAVStatus {
private:
	virtual HRESULT QueryInterface() = 0;
	virtual HRESULT AddRef() = 0;
	virtual HRESULT Release() = 0;

public:
	virtual HRESULT Register(wchar_t*, wchar_t*, int, int) = 0;
	virtual HRESULT Unregister(void) = 0;
	virtual HRESULT UpdateStatus(WSC_SECURITY_PRODUCT_STATE, int) = 0;
};

class IWscAVStatus4 {
private:
	virtual HRESULT QueryInterface() = 0;
	virtual HRESULT AddRef() = 0;
	virtual HRESULT Release() = 0;

public:
	virtual HRESULT Register(wchar_t*, wchar_t*, int, int) = 0;
	virtual HRESULT Unregister(void) = 0;
	virtual HRESULT UpdateStatus(WSC_SECURITY_PRODUCT_STATE, int) = 0;
	virtual HRESULT InitiateOfflineCleaning(wchar_t*, wchar_t*) = 0;
	virtual HRESULT NotifyUserForNearExpiration(ULONG64) = 0;
};

HRESULT WscControl(int cmd, wchar_t* displayName);
