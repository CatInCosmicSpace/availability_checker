#include <winsock2.h>
#include <winsock.h>
#include <winbase.h>
#include <cstdio>
#include <vector>
#include <iostream>
#include <getopt.h>
#include <fstream>
#include "httpslib.hpp"

typedef struct IPInfo {
    u_char ttl;             // Time To Live
    u_char tos;             // Type Of Service
    u_char ipFlags;         // IP flags
    u_char optSize;         // Size of options data
    u_char FAR *options;    // Options data buffer
} IPINFO, *PIPINFO;

typedef struct ICMPEcho {
    u_long Source;                  // Source address
    u_long Status;                  // IP status
    u_long RTTime;                  // Round trip time in milliseconds
    u_short DataSize;               // Reply data size
    u_short Reserved;               // Unknown
    void FAR *pData;                // Reply data buffer
    IPINFO ipInfo;                  // Reply options
} ICMPECHO, *PICMPECHO;


// ICMP.DLL Export Function Pointers
HANDLE (WINAPI *pIcmpCreateFile)(VOID);

BOOL (WINAPI *pIcmpCloseHandle)(HANDLE);

DWORD (WINAPI *pIcmpSendEcho)(HANDLE, DWORD, LPVOID, WORD, PIPINFO, LPVOID, DWORD, DWORD);

int pingNumber = 5;
std::string configFile = "addresses.txt";
std::string reportFile = "report.txt";

void printHelp() {
    std::cout << "--num <n>:                Set number of ping requests" << std::endl;
    std::cout << "--conf <fname>:           File with list of addresses" << std::endl;
    std::cout << "--report <fname>:         File to write report" << std::endl;
    std::cout << "--help:                   Show help" << std::endl;
}

void processArgs(int argc, char **argv) {
    const char *const short_opts = "n:c:r:";
    const option long_opts[] = {
            {"num",    required_argument, nullptr, 'n'},
            {"conf",   required_argument, nullptr, 'c'},
            {"report", required_argument, nullptr, 'r'},
            {"help",   no_argument,       nullptr, 'h'},
            {nullptr,  no_argument,       nullptr, 0}
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
        if (-1 == opt)
            break;
        switch (opt) {
            case 'n':
                pingNumber = std::stoi(optarg);
                std::cout << "Ping number set to: " << pingNumber << std::endl;
                break;
            case 'c':
                configFile = std::string(optarg);
                std::cout << "Config file set to: " << configFile << std::endl;
                break;
            case 'r':
                reportFile = std::string(optarg);
                std::cout << "Report file set to: " << reportFile << std::endl;
                break;
            case 'h': // -h or --help
            case '?': // Unrecognized option
            default:
                printHelp();
                exit(0);
        }
    }
}

int main(int argc, char **argv) {
    WSADATA wsaData;                // WSADATA
    ICMPECHO icmpEcho;              // ICMP Echo reply buffer
    HMODULE hndlIcmp;               // LoadLibrary() handle to ICMP.DLL
    HANDLE hndlFile = nullptr;                // Handle for IcmpCreateFile()
    LPHOSTENT pHost;                // Pointer to host entry structure
    struct in_addr iaDest{};        // Internet address structure
    DWORD *dwAddress;               // IP Address
    IPINFO ipInfo;                  // IP Options structure
    int nRet;                       // General use return code
    DWORD dwRet;                    // DWORD return code

    processArgs(argc, argv);

    // Dynamically load the ICMP.DLL
    hndlIcmp = LoadLibrary("ICMP.DLL");
    if (hndlIcmp == NULL) {
        std::cerr << "Could not load ICMP.DLL" << std::endl;
        return -1;
    }

    // Retrieve ICMP function pointers
    pIcmpCreateFile = (HANDLE (WINAPI *)(void)) GetProcAddress(hndlIcmp, "IcmpCreateFile");
    pIcmpCloseHandle = (BOOL (WINAPI *)(HANDLE)) GetProcAddress(hndlIcmp, "IcmpCloseHandle");
    pIcmpSendEcho = (DWORD (WINAPI *)(HANDLE, DWORD, LPVOID, WORD, PIPINFO, LPVOID, DWORD, DWORD))
            GetProcAddress(hndlIcmp, "IcmpSendEcho");
    // Check all the function pointers
    if (pIcmpCreateFile == NULL || pIcmpCloseHandle == NULL || pIcmpSendEcho == NULL) {
        std::cerr << "Error getting ICMP proc address" << std::endl;
        FreeLibrary(hndlIcmp);
        return -1;
    }

    // Init WinSock
    nRet = WSAStartup(0x0101, &wsaData);
    if (nRet) {
        std::cerr << "WSAStartup() error: " << nRet << std::endl;
        WSACleanup();
        FreeLibrary(hndlIcmp);
        return -1;
    }
    // Check WinSock version
    if (0x0101 != wsaData.wVersion) {
        std::cerr << "WinSock version 1.1 not supported" << std::endl;
        WSACleanup();
        FreeLibrary(hndlIcmp);
        return -1;
    }

    std::ifstream config(configFile);
    std::ofstream report(reportFile);
    std::string line;
    std::vector<std::string> addresses;
    std::string reportString;
    while (std::getline(config, line)) {
        if (!line.empty()) {
            auto cLine = line.c_str();
            iaDest.s_addr = inet_addr(cLine);
            if (iaDest.s_addr == INADDR_NONE) {
                pHost = gethostbyname(cLine);
            } else {
                pHost = gethostbyaddr((const char *) &iaDest, sizeof(struct in_addr), AF_INET);
            }
            if (pHost == NULL) {
                std::cerr << cLine << " not found" << std::endl;
                report << cLine << " is not available" << std::endl;
                reportString += cLine;
                reportString += " is not available\n";
                continue;
            }
            std::cout << "Pinging " << pHost->h_name << " [" << inet_ntoa((*(LPIN_ADDR) pHost->h_addr_list[0])) << "]"
                      << std::endl;
            dwAddress = (DWORD *) (*pHost->h_addr_list);        // Copy the IP address
            hndlFile = pIcmpCreateFile();                       // Get an ICMP echo request handle
            for (int i = 0; i < pingNumber; i++) {
                // Set some reasonable default values
                ipInfo.ttl = 255;
                ipInfo.tos = 0;
                ipInfo.ipFlags = 0;
                ipInfo.optSize = 0;
                ipInfo.options = NULL;
                // Reqest an ICMP echo
                pIcmpSendEcho(
                        hndlFile,               // Handle from IcmpCreateFile()
                        *dwAddress,             // Destination IP address
                        NULL,                   // Pointer to buffer to send
                        0,                      // Size of buffer in bytes
                        &ipInfo,                // Request options
                        &icmpEcho,              // Reply buffer
                        sizeof(struct ICMPEcho),
                        5000                    // Time to wait in milliseconds
                );
                // Print the results
                iaDest.s_addr = icmpEcho.Source;
                std::cout << "Reply from " << inet_ntoa(iaDest) << ", Time = " << icmpEcho.RTTime << " ms, TTL = "
                          << (int) icmpEcho.ipInfo.ttl << std::endl;
                if (icmpEcho.Status) {
                    std::cout << "Error: icmpEcho.Status = " << icmpEcho.Status << std::endl;
                    continue;
                }
            }
            report << cLine << " is available" << std::endl;
            reportString += cLine;
            reportString += " is available\n";
        }
    }

#define HOST_CERT "fullchain.pem"
    HTTPSClient client("skypebot.tk", 8081, HOST_CERT);
    HTTPResponse result = client.post("/report", reportString, "text/plain");
    if (result)
        std::cout << result.body << std::endl;
    else
        std::cout << result.ret_code << " " << result.message << std::endl;

    // Close the echo request file handle
    pIcmpCloseHandle(hndlFile);
    report.close();
    config.close();
    FreeLibrary(hndlIcmp);
    WSACleanup();
    return 0;
}