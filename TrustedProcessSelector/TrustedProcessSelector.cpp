/*****************************************************
 * 文件名：trusted_process_selector.cpp
 * 版本号：1.0.0
 * 创建日期：2025-05-13
 * 描述：扫描Windows系统中具有强制完整性标志并且经过数字签名的可执行文件
 *       用于安全研究和系统管理，可以用来识别合适的"傀儡"进程
 * 已通过编译环境：C++11
 *****************************************************/

#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <tchar.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <functional>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shlwapi.lib")

 // 扫描配置常量
const std::string kTargetDirectory = "c:\\Windows\\System32";
const std::set<std::string> kTargetFileExts = { ".exe" };

// PE文件格式常量
const WORD kDosMagic = 0x5A4D;             // MZ标记
const DWORD kNtSignature = 0x00004550;     // PE\0\0标记
const WORD kArm64Machine = 0xAA64;         // ARM64架构
const WORD kAmd64Machine = 0x8664;         // x64架构
const WORD kI386Machine = 0x014C;          // x86架构
const WORD kDllCharacteristicsForceIntegrity = 0x80; // 强制完整性标志位

/**********************************************************
 * 功能：将字符串转换为小写
 * 参数：str - 要转换的字符串
 * 返回：转换后的小写字符串
 * 备注：
 **********************************************************/
std::string ToLower(const std::string& str) {
	std::string result = str;
	std::transform(result.begin(), result.end(), result.begin(),
				   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
	return result;
}

/**********************************************************
 * 功能：获取文件扩展名
 * 参数：filePath - 文件路径
 * 返回：文件扩展名（小写）
 * 备注：
 **********************************************************/
std::string GetFileExtension(const std::string& filePath) {
	const char* ext = ::PathFindExtensionA(filePath.c_str());
	return ToLower(ext ? ext : "");
}

/**********************************************************
 * 功能：获取文件大小
 * 参数：filePath - 文件路径
 * 返回：文件大小（字节数）
 * 备注：
 **********************************************************/
DWORD GetFileSize(const std::string& filePath) {
	WIN32_FILE_ATTRIBUTE_DATA fileAttrData = { 0 };
	if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileAttrData)) {
		ULARGE_INTEGER size;
		size.LowPart = fileAttrData.nFileSizeLow;
		size.HighPart = fileAttrData.nFileSizeHigh;
		return static_cast<DWORD>(size.QuadPart);
	}
	return 0;
}

/**********************************************************
 * 功能：读取指定路径的文件内容到内存缓冲区
 * 参数：filePath - 目标文件的路径
 * 返回：包含文件内容的缓冲区，如果读取失败则返回空vector
 * 备注：使用二进制模式读取整个文件
 **********************************************************/
std::vector<uint8_t> ReadFile(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary);
	if (!file.good()) {
		return std::vector<uint8_t>();
	}

	DWORD fileSize = GetFileSize(filePath);
	if (fileSize == 0) {
		return std::vector<uint8_t>();
	}

	std::vector<uint8_t> buffer(fileSize);
	file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

	return buffer;
}

/**********************************************************
 * 功能：检查PE文件是否设置了强制完整性检查标志
 * 参数：data - 包含PE文件内容的数据缓冲区
 *       size - 数据缓冲区的大小
 * 返回：true表示设置了强制完整性标志，false表示未设置
 * 备注：分析PE文件结构，支持x86、x64和ARM64架构
 **********************************************************/
bool CheckIntegrityFlag(const uint8_t* data, size_t size) {
	if (size < sizeof(IMAGE_DOS_HEADER)) {
		throw std::runtime_error("无效的PE文件：文件过小");
	}

	const auto pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
	if (pDosHeader->e_magic != kDosMagic) {
		throw std::runtime_error("无效的PE文件：DOS头部魔数不匹配");
	}

	if (size < static_cast<size_t>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS)) {
		throw std::runtime_error("无效的PE文件：NT头部不完整");
	}

	const auto pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != kNtSignature) {
		throw std::runtime_error("无效的PE文件：NT头部签名不匹配");
	}

	const auto machine = pNtHeaders->FileHeader.Machine;
	WORD characteristics = 0;

	if (machine == kArm64Machine || machine == kAmd64Machine) {
		characteristics = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pNtHeaders)->OptionalHeader.DllCharacteristics;
	}
	else if (machine == kI386Machine) {
		characteristics = reinterpret_cast<const IMAGE_NT_HEADERS32*>(pNtHeaders)->OptionalHeader.DllCharacteristics;
	}
	else {
		char errorMsg[100];
		sprintf_s(errorMsg, "不支持的机器类型: 0x%X", machine);
		throw std::runtime_error(errorMsg);
	}

	return (characteristics & kDllCharacteristicsForceIntegrity) != 0;
}

/**********************************************************
 * 功能：检查文件是否具有有效的数字签名
 * 参数：filePath - 文件路径
 * 返回：true表示有有效签名，false表示无有效签名
 * 备注：使用Windows加密API验证文件的数字签名
 **********************************************************/
bool CheckSignature(const std::string& filePath) {
	// 将路径转换为宽字符
	std::wstring wFilePath;
	int requiredSize = MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, NULL, 0);
	if (requiredSize > 0) {
		wFilePath.resize(requiredSize);
		MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, &wFilePath[0], requiredSize);
	}
	else {
		return false;
	}

	HCERTSTORE certStore = nullptr;
	HCRYPTMSG cryptMsg = nullptr;
	bool result = false;

	// 查询并验证文件的签名信息
	BOOL querySuccess = CryptQueryObject(
		CERT_QUERY_OBJECT_FILE,          // 查询对象类型为文件
		wFilePath.c_str(),               // 文件路径
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,  // 内容类型标志
		CERT_QUERY_FORMAT_FLAG_BINARY,   // 格式标志
		0,                               // 保留参数
		nullptr,                         // 不需要加密编码类型
		nullptr,                         // 不需要内容类型
		nullptr,                         // 不需要格式类型
		&certStore,                      // 返回的证书存储
		&cryptMsg,                       // 返回的消息句柄
		nullptr                          // 不需要上下文
	);

	if (!querySuccess || !certStore || !cryptMsg) {
		// 文件可能未签名
		return false;
	}

	// 创建签名者上下文
	PCCERT_CONTEXT signer = nullptr;
	BOOL signerSuccess = CryptMsgGetAndVerifySigner(
		cryptMsg,                 // 消息句柄
		0,                        // 保留参数
		nullptr,                 // 不需要获取签名者数组
		CMSG_VERIFY_SIGNER_CERT,  // 验证签名者证书
		&signer,                  // 签名者证书
		nullptr                  // 不需要调整验证状态
	);

	if (signerSuccess && signer != nullptr) {
		result = true;
		CertFreeCertificateContext(signer);
	}

	// 释放资源
	if (cryptMsg) {
		CryptMsgClose(cryptMsg);
	}
	if (certStore) {
		CertCloseStore(certStore, CERT_CLOSE_STORE_FORCE_FLAG);
	}

	return result;
}

/**********************************************************
 * 功能：搜索目录中的文件
 * 参数：directory - 要搜索的目录路径
 *       callback - 处理找到的文件的回调函数
 * 返回：无
 * 备注：使用Windows API递归搜索文件
 **********************************************************/
void FindFiles(const std::string& directory,
			   std::function<void(const std::string&)> callback) {
	WIN32_FIND_DATAA findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	std::string searchPath = directory + "\\*";
	hFind = FindFirstFileA(searchPath.c_str(), &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		return;
	}

	do {
		if (strcmp(findFileData.cFileName, ".") == 0 ||
			strcmp(findFileData.cFileName, "..") == 0) {
			continue;
		}

		std::string filePath = directory + "\\" + findFileData.cFileName;

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// 递归搜索子目录
			FindFiles(filePath, callback);
		}
		else {
			// 处理文件
			callback(filePath);
		}
	} while (FindNextFileA(hFind, &findFileData) != 0);

	FindClose(hFind);
}


/**********************************************************
 * 功能：主函数 - 扫描System32目录，选择符合安全要求的进程
 * 返回：成功返回EXIT_SUCCESS，失败返回EXIT_FAILURE
 * 备注：查找同时满足两个条件的Windows可执行文件：
 *       1. 设置了强制完整性检查标志(Force Integrity)
 *       2. 具有有效的数字签名
 *       这类文件通常是安全的系统组件，可作为可信的"傀儡"进程
 **********************************************************/
int main() {
	try {
		std::cout << "TrustedProcessSelector v1.0 - 可信进程扫描器\n";
		std::cout << "正在扫描 " << kTargetDirectory << " 中的可执行文件...\n\n";

		int totalChecked = 0;
		int matchesFound = 0;

		// 使用FindFiles函数替代std::filesystem
		FindFiles(kTargetDirectory, [&](const std::string& filePath) {
			// 检查文件扩展名
			std::string ext = GetFileExtension(filePath);
			if (kTargetFileExts.find(ext) == kTargetFileExts.end()) {
				return;
			}

			totalChecked++;

			// 读取文件内容
			std::vector<uint8_t> fileData = ReadFile(filePath);
			if (fileData.empty()) {
				std::cerr << "无法读取文件: " << filePath << std::endl;
				return;
			}

			try {
				// 检查文件是否设置了强制完整性标志
				if (!CheckIntegrityFlag(fileData.data(), fileData.size())) {
					return;
				}

				// 检查文件是否有有效签名
				if (!CheckSignature(filePath)) {
					return;
				}

				// 如果同时满足两个条件，输出匹配结果
				std::cout << "[已找到] " << filePath << std::endl;
				matchesFound++;
			}
			catch (const std::exception& e) {
				std::cerr << "处理文件 " << filePath << " 时出错: " << e.what() << std::endl;
			}
				  });

		std::cout << "\n扫描完成：检查了 " << totalChecked << " 个文件，找到 "
			<< matchesFound << " 个匹配的可信进程\n";
		std::cout << "请按任意键继续...\n";
		system("pause");
		return EXIT_SUCCESS;
	}
	catch (const std::exception& e) {
		std::cerr << "致命错误: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
}