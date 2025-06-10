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

std::unordered_set<std::string> LoadSignatures(const std::string& filename) {
    std::unordered_set<std::string> signatures;
    std::ifstream file(filename);
    std::string hash;
    while (std::getline(file, hash)) {
        if (!hash.empty()) signatures.insert(hash);
    }
    return signatures;
}

std::string GetMD5(const std::string& filepath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[1024];
    DWORD bytesRead;
    BYTE hash[16];
    DWORD hashLen = 16;
    std::string result;

    HANDLE file = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return "";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(file);
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(file);
        return "";
    }

    while (ReadFile(file, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(file);
            return "";
        }
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        char hex[33] = { 0 };
        for (DWORD i = 0; i < hashLen; ++i) {
            sprintf(hex + i * 2, "%02x", hash[i]);
        }
        result = hex;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(file);

    return result;
}

void ScanDirectory(const std::string& path, const std::unordered_set<std::string>& signatures) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
        if (!entry.is_regular_file()) continue;
        std::string filepath = entry.path().string();
        std::string fileHash = GetMD5(filepath);
        if (signatures.find(fileHash) != signatures.end()) {
            std::cout << "[THREAT] " << filepath << " matches known signature." << std::endl;
            std::string quarantinePath = "quarantine\\" + entry.path().filename().string();
            std::filesystem::create_directory("quarantine");
            std::filesystem::rename(filepath, quarantinePath);
        }
    }
}

void ScanMemory(const std::unordered_set<std::string>& signatures) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION memInfo;
    BYTE buffer[1024];
    for (BYTE* addr = 0; addr < sysInfo.lpMaximumApplicationAddress; addr += memInfo.RegionSize) {
        if (VirtualQuery(addr, &memInfo, sizeof(memInfo))) {
            if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_READWRITE)) {
                SIZE_T bytesRead;
                HANDLE process = GetCurrentProcess();
                if (ReadProcessMemory(process, addr, buffer, sizeof(buffer), &bytesRead)) {
                    HCRYPTPROV hProv = 0;
                    HCRYPTHASH hHash = 0;
                    BYTE hash[16];
                    DWORD hashLen = 16;
                    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                            CryptHashData(hHash, buffer, bytesRead, 0);
                            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                                char hex[33] = { 0 };
                                for (DWORD i = 0; i < hashLen; ++i)
                                    sprintf(hex + i * 2, "%02x", hash[i]);
                                if (signatures.find(hex) != signatures.end()) {
                                    std::cout << "[MEMORY THREAT] At address: " << static_cast<void*>(addr) << std::endl;
                                }
                            }
                            CryptDestroyHash(hHash);
                        }
                        CryptReleaseContext(hProv, 0);
                    }
                }
            }
        }
    }
}

void ScanProcesses(const std::unordered_set<std::string>& signatures) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (hProcess) {
                HMODULE hMods[1024];
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
                        char modName[MAX_PATH];
                        if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
                            std::string hash = GetMD5(modName);
                            if (signatures.find(hash) != signatures.end()) {
                                std::cout << "[PROCESS MODULE THREAT] " << modName << std::endl;
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
    auto signatures = LoadSignatures("signatures.txt");
    if (signatures.empty()) {
        std::cerr << "No signatures loaded.\n";
        return 1;
    }

    std::string scanPath = "C:\\Users\\Public";
    ScanDirectory(scanPath, signatures);
    ScanMemory(signatures);
    ScanProcesses(signatures);

    std::cout << "Scan complete.\n";
    return 0;
}
