
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <string>
#include <iomanip>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>

#pragma comment (lib, "Advapi32.lib")
#pragma comment (lib, "Crypt32.lib")
#pragma comment (lib, "Psapi.lib")

namespace fs = std::filesystem;

std::unordered_set<std::string> LoadSignatures(const std::string& path) {
    std::unordered_set<std::string> sigs;
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) sigs.insert(line);
    return sigs;
}

std::string GetMD5(const std::string& filename) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[1024];
    DWORD bytesRead;
    BYTE hash[16];
    DWORD hashLen = 16;
    std::ostringstream result;
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) return "";
    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || (bytesRead = file.gcount())) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) return "";
    }
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        for (DWORD i = 0; i < hashLen; ++i)
            result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result.str();
}

void QuarantineFile(const std::string& filePath) {
    std::string quarantinePath = "C:\\Quarantine\\" + fs::path(filePath).filename().string();
    fs::create_directories("C:\Quarantine\");
    fs::rename(filePath, quarantinePath);
}

void ScanDirectory(const std::string& directory, const std::unordered_set<std::string>& signatures) {
    for (auto& entry : fs::recursive_directory_iterator(directory)) {
        if (fs::is_regular_file(entry.path())) {
            std::string hash = GetMD5(entry.path().string());
            if (signatures.find(hash) != signatures.end()) {
                std::cout << "[INFECTED] " << entry.path() << std::endl;
                QuarantineFile(entry.path().string());
            }
        }
    }
}

void ListSuspiciousProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe32)) {
        do {
            std::string proc = pe32.szExeFile;
            if (proc == "powershell.exe" || proc == "wscript.exe" || proc == "cmd.exe" || proc == "mshta.exe") {
                std::cout << "[SUSPICIOUS] Running process: " << proc << std::endl;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

void ScanMemoryRegions() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION memInfo;
    unsigned char* addr = 0;
    while (addr < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQuery(addr, &memInfo, sizeof(memInfo))) {
            if (memInfo.State == MEM_COMMIT && memInfo.Type == MEM_PRIVATE && memInfo.Protect == PAGE_EXECUTE_READWRITE) {
                std::cout << "[MEMORY] Executable and writable memory region found at: " << (void*)addr << std::endl;
            }
            addr += memInfo.RegionSize;
        } else break;
    }
}

void ScanLoadedModules() {
    DWORD processes[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) return;
    cProcesses = cbNeeded / sizeof(DWORD);
    for (unsigned int i = 0; i < cProcesses; ++i) {
        if (processes[i] != 0) {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess) {
                HMODULE hMod;
                DWORD cbNeededModule;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededModule)) {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                    std::wcout << L"[MODULE] " << szProcessName << std::endl;
                }
                CloseHandle(hProcess);
            }
        }
    }
}

int main() {
    auto signatures = LoadSignatures("signatures.txt");
    ScanDirectory("C:\Users\Public", signatures);
    ListSuspiciousProcesses();
    ScanMemoryRegions();
    ScanLoadedModules();
    return 0;
}
