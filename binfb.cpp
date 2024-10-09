#include "binfb.h"
#include "utils.h"
#include <windows.h>
#include <vector>
#include <cstdint>
#include <iostream>
#include "scanner/scanner.h"
#include "hooks.h"
#include "memory.hpp"
#include <string>
#include <wininet.h>
#include <sstream>
#include <algorithm>
#pragma comment(lib, "wininet.lib")

uintptr_t rva_to_absolute(HMODULE module, uintptr_t rva) {
    return reinterpret_cast<uintptr_t>(module) + rva;
}

binfb_t::binfb_t(HMODULE mod)
{
    SetConsoleTitleA("Cracked by yours truly");
}

std::string DownloadSignatures(const std::string& url) {
    std::string data;
    HINTERNET hInternet = InternetOpenA("UserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION, 0);
        if (hConnect) {
            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                data.append(buffer, bytesRead);
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
    }
    return data;
}

void patch_vmp()
{
    unsigned long old_protect = 0;
    const auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return;

    unsigned char callcode = *reinterpret_cast<unsigned char*>(reinterpret_cast<uintptr_t>(GetProcAddress(ntdll, "NtQuerySection")) + 4) - 1;
    unsigned char restore[] = { 0x4C, 0x8B, 0xD1, 0xB8, callcode };

    const auto nt_protect_virtual_mem = reinterpret_cast<uintptr_t>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
    if (!nt_protect_virtual_mem)
        return;

    VirtualProtect(reinterpret_cast<LPVOID>(nt_protect_virtual_mem), sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(reinterpret_cast<void*>(nt_protect_virtual_mem), restore, sizeof(restore));
    VirtualProtect(reinterpret_cast<LPVOID>(nt_protect_virtual_mem), sizeof(restore), old_protect, &old_protect);
}

void fill_with_nop(std::uintptr_t addr)
{
    unsigned long old_protect;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *reinterpret_cast<uint8_t*>(addr) = 0x90; // NOP instruction
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, old_protect, &old_protect);
}

void fill_with_je(std::uintptr_t addr)
{
    unsigned long old_protect;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *reinterpret_cast<uint8_t*>(addr) = 0x74; // JE instruction
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, old_protect, &old_protect);
}

void fill_with_jne(std::uintptr_t addr)
{
    unsigned long old_protect;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 6, PAGE_EXECUTE_READWRITE, &old_protect);

    // Handle both short (0x74) and long (0x0F 0x84) JE instructions
    if (*reinterpret_cast<uint8_t*>(addr) == 0x74) {
        *reinterpret_cast<uint8_t*>(addr) = 0x75; // Short JNE instruction
    }
    else if (*reinterpret_cast<uint8_t*>(addr) == 0x0F && *reinterpret_cast<uint8_t*>(addr + 1) == 0x84) {
        *reinterpret_cast<uint8_t*>(addr + 1) = 0x85; // Long JNE instruction
    }
    else {
        MessageBoxA(NULL, "Invalid JE instruction", "Error", MB_OK | MB_ICONERROR);
    }

    VirtualProtect(reinterpret_cast<LPVOID>(addr), 6, old_protect, &old_protect);
}

void binfb_t::patches()
{
    // Download signatures from PasteBin link
    std::string signaturesData = DownloadSignatures("https://pastebin.com/raw/Pj8DahvQ");
    if (signaturesData.empty()) {
        MessageBoxA(NULL, "Failed to download signatures data", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Parse the downloaded data to extract signatures
    std::vector<std::string> signatures;
    std::istringstream iss(signaturesData);
    std::string signature;
    while (std::getline(iss, signature)) {
        // Trim leading and trailing whitespaces
        signature.erase(std::remove_if(signature.begin(), signature.end(), [](char c) { return std::isspace(c); }), signature.end());
        if (!signature.empty()) {
            signatures.push_back(signature);
        }
    }

    // Get the base address of the module
    HMODULE module = GetModuleHandleA(NULL);
    if (!module) {
        MessageBoxA(NULL, "Failed to get module handle", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Loop through each signature to find the addresses of the instructions
    for (const auto& signature : signatures) {
        // Split the signature into RVA and description
        size_t pos = signature.find("|");
        if (pos == std::string::npos) {
            MessageBoxA(NULL, "Invalid signature format", "Error", MB_OK | MB_ICONERROR);
            continue;
        }
        std::string rvaStr = signature.substr(0, pos);
        std::string description = signature.substr(pos + 1);

        // Convert RVA string to uint64_t
        uintptr_t rva = std::stoull(rvaStr, nullptr, 16);

        // Convert RVA to absolute address
        uintptr_t address = rva_to_absolute(module, rva);

        // If the address is valid, perform the patching
        if (address != 0) {
            if (description.find("NOP") != std::string::npos) {
                fill_with_nop(address);
            }
            else if (description.find("JNE2JE") != std::string::npos) {
                fill_with_je(address);
            }
            else if (description.find("JE2JNE") != std::string::npos) {
                fill_with_jne(address);
            }
            else {
                MessageBoxA(NULL, ("Unknown patch description: " + description).c_str(), "Error", MB_OK | MB_ICONERROR);
            }
        }
        else {
            MessageBoxA(NULL, ("Invalid address for RVA: " + rvaStr).c_str(), "Error", MB_OK | MB_ICONERROR);
        }
    }

    MessageBoxA(NULL, "Cracked by od8m", "Bin-fb", MB_OK);
}

void core(HMODULE mod)
{
    std::uintptr_t integrity = scanner()->find_pattern("E8 ? ? ? ? 48 8D 4D 17").get();

    if (is_bad_ptr(integrity))
    {
        MessageBoxA(NULL, "Integrity check not found", "Bin-fb", MB_OK);
    }
    else
    {
        MessageBoxA(NULL, "[BinaryFemboys] Welcome! Enjoy free software :)", "yours truly", MB_OK);
        mem_hook->NopMemory(integrity);
    }

    binfb_t* cheat = new binfb_t(mod);
    patch_vmp();
    cheat->patches();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        DisableThreadLibraryCalls(GetModuleHandleA(0));

        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)core, hModule, 0, 0);
    }

    return TRUE;
}