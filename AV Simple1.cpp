#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include <filesystem>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Advapi32.lib")

std::unordered_set<std::string> LoadSignatures(const std::string& filename) {
    std::unordered_set<std::string> signatures;
    std::ifstream file(filename);
    std::string hash;
    while (std::getline(file, hash)) {
        if (!hash.empty())
            signatures.insert(hash);
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
    if (file == INVALID_HANDLE_VALUE)
        return "";

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
        char hex[33] = {0};
        for (DWORD i = 0; i < hashLen; ++i)
            sprintf(hex + i * 2, "%02x", hash[i]);
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

int main() {
    std::unordered_set<std::string> signatures = LoadSignatures("signatures.txt");

    if (signatures.empty()) {
        std::cerr << "No signatures loaded. Exiting." << std::endl;
        return 1;
    }

    std::string scanPath = "C:\\Users\\Public";
    ScanDirectory(scanPath, signatures);

    std::cout << "Scan complete." << std::endl;
    return 0;
}
