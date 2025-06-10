#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

// Load known malware MD5 hashes from a text file
std::unordered_set<std::string> LoadKnownSignatures(const std::string& filepath) {
    std::unordered_set<std::string> hashes;
    std::ifstream infile(filepath);
    std::string hash;

    while (std::getline(infile, hash)) {
        if (!hash.empty()) {
            hashes.insert(hash);
        }
    }

    return hashes;
}

// Compute the MD5 hash of a memory buffer
std::string GetMD5Hash(const BYTE* data, DWORD size) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE result[16];
    DWORD resultLen = sizeof(result);
    char hexOutput[33] = {};

    if (!CryptAcquireContext(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    if (!CryptCreateHash(provider, CALG_MD5, 0, 0, &hash)) {
        CryptReleaseContext(provider, 0);
        return {};
    }

    if (!CryptHashData(hash, data, size, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }

    if (!CryptGetHashParam(hash, HP_HASHVAL, result, &resultLen, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }

    for (int i = 0; i < 16; ++i) {
        snprintf(hexOutput + i * 2, 3, "%02x", result[i]);
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);

    return std::string(hexOutput);
}

// Scan all files in a folder and compare their MD5 hashes with known signatures
void ScanFolder(const std::string& folderPath, const std::unordered_set<std::string>& knownHashes) {
    WIN32_FIND_DATA fileData;
    std::string searchPath = folderPath + "\\*";
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &fileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open folder: " << folderPath << "\n";
        return;
    }

    do {
        if (!(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string fullPath = folderPath + "\\" + fileData.cFileName;
            std::ifstream file(fullPath, std::ios::binary | std::ios::ate);
            if (file) {
                auto size = static_cast<DWORD>(file.tellg());
                file.seekg(0, std::ios::beg);
                std::vector<BYTE> buffer(size);
                file.read(reinterpret_cast<char*>(buffer.data()), size);

                std::string hash = GetMD5Hash(buffer.data(), size);
                if (knownHashes.count(hash)) {
                    std::cout << "[!] Threat detected in file: " << fullPath << "\n";
                }
            }
        }
    } while (FindNextFile(hFind, &fileData));

    FindClose(hFind);
}

// Scan current process memory
void ScanOwnMemory(const std::unordered_set<std::string>& knownHashes) {
    MEMORY_BASIC_INFORMATION memInfo = {};
    BYTE* addr = nullptr;

    while (VirtualQuery(addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
        if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_READWRITE)) {
            std::vector<BYTE> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(GetCurrentProcess(), addr, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                std::string hash = GetMD5Hash(buffer.data(), static_cast<DWORD>(bytesRead));
                if (knownHashes.count(hash)) {
                    std::cout << "[!] Threat detected in memory at address: " << static_cast<void*>(addr) << "\n";
                }
            }
        }

        addr += memInfo.RegionSize;
    }
}

// Scan loaded modules of running processes
void ScanAllProcesses(const std::unordered_set<std::string>& knownHashes) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot\n";
        return;
    }

    PROCESSENTRY32 entry = { sizeof(entry) };
    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
        if (hProcess) {
            HMODULE modules[1024];
            DWORD needed;
            if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
                for (unsigned i = 0; i < needed / sizeof(HMODULE); ++i) {
                    TCHAR modPath[MAX_PATH];
                    if (GetModuleFileNameEx(hProcess, modules[i], modPath, MAX_PATH)) {
                        std::ifstream file(modPath, std::ios::binary | std::ios::ate);
                        if (file) {
                            auto size = static_cast<DWORD>(file.tellg());
                            file.seekg(0, std::ios::beg);
                            std::vector<BYTE> buffer(size);
                            file.read(reinterpret_cast<char*>(buffer.data()), size);

                            std::string hash = GetMD5Hash(buffer.data(), size);
                            if (knownHashes.count(hash)) {
                                std::wcout << L"[!] Threat found in process " << entry.szExeFile << L": " << modPath << "\n";
                            }
                        }
                    }
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
}

int main() {
    const std::string signatureFile = "signatures.txt";
    const std::string scanDir = "C:\\target_folder";

    auto knownHashes = LoadKnownSignatures(signatureFile);

    std::cout << "[*] Scanning directory: " << scanDir << "\n";
    ScanFolder(scanDir, knownHashes);

    std::cout << "[*] Scanning current process memory...\n";
    ScanOwnMemory(knownHashes);

    std::cout << "[*] Scanning running processes...\n";
    ScanAllProcesses(knownHashes);

    std::cout << "[✓] Scan complete.\n";
    return 0;
}
