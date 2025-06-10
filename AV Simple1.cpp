#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>

#pragma comment(lib, "Advapi32.lib")

// Load known threat hashes from a file into a set
std::unordered_set<std::string> LoadSignatures(const std::string& filename) {
    std::unordered_set<std::string> signatures;
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Failed to open signature file: " << filename << std::endl;
        return signatures;
    }

    std::string hash;
    while (std::getline(file, hash)) {
        if (!hash.empty()) {
            signatures.insert(hash);
        }
    }

    return signatures;
}

// Compute MD5 hash of a file
std::string GetMD5Hash(const BYTE* buffer, DWORD length) {
    HCRYPTPROV cryptoProvider = 0;
    HCRYPTHASH hashHandle = 0;
    BYTE md5[16];
    DWORD md5Len = sizeof(md5);
    char result[33] = {};

    if (!CryptAcquireContext(&cryptoProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    if (!CryptCreateHash(cryptoProvider, CALG_MD5, 0, 0, &hashHandle)) {
        CryptReleaseContext(cryptoProvider, 0);
        return {};
    }

    if (!CryptHashData(hashHandle, buffer, length, 0)) {
        CryptDestroyHash(hashHandle);
        CryptReleaseContext(cryptoProvider, 0);
        return {};
    }

    if (!CryptGetHashParam(hashHandle, HP_HASHVAL, md5, &md5Len, 0)) {
        CryptDestroyHash(hashHandle);
        CryptReleaseContext(cryptoProvider, 0);
        return {};
    }

    for (int i = 0; i < 16; ++i) {
        snprintf(result + i * 2, 3, "%02x", md5[i]);
    }

    CryptDestroyHash(hashHandle);
    CryptReleaseContext(cryptoProvider, 0);

    return std::string(result);
}


// Scan files in a directory and quarantine if matched with known threats
void ScanDirectory(const std::string& rootPath, const std::unordered_set<std::string>& signatures) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath)) {
        if (!entry.is_regular_file()) continue;

        std::string filepath = entry.path().string();
        std::string hash = ComputeMD5(filepath);

        if (!hash.empty() && signatures.find(hash) != signatures.end()) {
            std::cout << "[THREAT] File: " << filepath << " matches known signature.\n";

            std::filesystem::create_directory("quarantine");
            std::filesystem::path quarantinePath = std::filesystem::path("quarantine") / entry.path().filename();
            try {
                std::filesystem::rename(filepath, quarantinePath);
            } catch (const std::exception& e) {
                std::cerr << "Failed to quarantine file: " << e.what() << '\n';
            }
        }
    }
}

// Scan current process memory for known threat signatures
void ScanMemory(const std::unordered_set<std::string>& signatures) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION memInfo;
    BYTE buffer[1024];

    for (BYTE* addr = 0; addr < sysInfo.lpMaximumApplicationAddress; addr += memInfo.RegionSize) {
        if (!VirtualQuery(addr, &memInfo, sizeof(memInfo))) continue;
        if (memInfo.State != MEM_COMMIT || !(memInfo.Protect & PAGE_READWRITE)) continue;

        SIZE_T bytesRead;
        HANDLE process = GetCurrentProcess();
        if (ReadProcessMemory(process, addr, buffer, sizeof(buffer), &bytesRead)) {
            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;
            BYTE hash[16];
            DWORD hashLen = sizeof(hash);

            if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                    CryptHashData(hHash, buffer, bytesRead, 0);
                    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                        char hex[33] = { 0 };
                        for (DWORD i = 0; i < hashLen; ++i)
                            sprintf(hex + i * 2, "%02x", hash[i]);

                        if (signatures.find(hex) != signatures.end()) {
                            std::cout << "[MEMORY THREAT] Detected at address: " << static_cast<void*>(addr) << '\n';
                        }
                    }
                    CryptDestroyHash(hHash);
                }
                CryptReleaseContext(hProv, 0);
            }
        }
    }
}

// Scan loaded modules in all running processes
void ScanProcesses(const std::unordered_set<std::string>& signatures) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    if (Process32First(snapshot, &entry)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (hProcess) {
                HMODULE modules[1024];
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
                    for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
                        char moduleName[MAX_PATH];
                        if (GetModuleFileNameExA(hProcess, modules[i], moduleName, MAX_PATH)) {
                            std::string hash = ComputeMD5(moduleName);
                            if (!hash.empty() && signatures.find(hash) != signatures.end()) {
                                std::cout << "[PROCESS MODULE THREAT] In process " << entry.szExeFile << ": " << moduleName << '\n';
                            }
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

int main() {
    const std::string signatureFile = "signatures.txt";
    const std::string scanPath = "C:\\Users\\Public";

    auto signatures = LoadSignatures(signatureFile);
    if (signatures.empty()) {
        std::cerr << "Error: No threat signatures loaded.\n";
        return 1;
    }

    std::cout << "Starting file system scan...\n";
    ScanDirectory(scanPath, signatures);

    std::cout << "Scanning process memory...\n";
    ScanMemory(signatures);

    std::cout << "Scanning running processes...\n";
    ScanProcesses(signatures);

    std::cout << "Scan complete.\n";
    return 0;
}
