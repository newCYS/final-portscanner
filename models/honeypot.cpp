#include "honeypot.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <ctime>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
    typedef int socklen_t;
    #ifndef _SSIZE_T_DEFINED
        #define _SSIZE_T_DEFINED
        #undef ssize_t
        #ifdef _WIN64
            typedef __int64 ssize_t;
        #else
            typedef int ssize_t;
        #endif
    #endif
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#define MAX_PENDING_CONNECTIONS 10

void run_honeypot(int port, const std::string& banner) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }
#endif

    int listen_fd, conn_fd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    std::cout << "[*] Starting honeypot on port " << port << "...\n";

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        return;
    }

    int enable_reuse = 1;
    int result = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, 
                            (const char*)&enable_reuse, sizeof(enable_reuse));

    if (result < 0) {
        perror("Failed to set socket option SO_REUSEADDR");
        close(listen_fd);
        return;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(static_cast<u_short>(port));

    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed");
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen failed");
        close(listen_fd);
        return;
    }

    std::cout << "[*] Honeypot listening for connections...\n";

    while (true) {
        conn_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (conn_fd < 0) {
            perror("accept failed");
            continue;
        }

        time_t now = time(0);
        char* dt = ctime(&now);
        if (dt[strlen(dt) - 1] == '\n') {
            dt[strlen(dt) - 1] = '\0';
        }

        std::cout << "--------------------------------------------------\n";
        std::cout << "[!] Connection detected!\n";
        std::cout << "[*] Time: " << dt << "\n";
        std::cout << "[*] Source IP: " << inet_ntoa(cli_addr.sin_addr) << "\n";
        std::cout << "[*] Source Port: " << ntohs(cli_addr.sin_port) << "\n";
        std::cout << "[*] Target Port: " << port << "\n";
        
        if (!banner.empty()) {
            std::string full_banner = banner + "\r\n";
            send(conn_fd, full_banner.c_str(), static_cast<int>(full_banner.length()), 0);
            std::cout << "[*] Sent banner: \"" << banner << "\"\n";
        }

        char buffer[1024] = {0};
        ssize_t valread = recv(conn_fd, buffer, 1024, 0);
        if (valread > 0) {
            std::cout << "[*] Received data: " << std::string(buffer, valread) << "\n";
        }

        close(conn_fd);
        std::cout << "[*] Connection closed.\n";
        std::cout << "--------------------------------------------------\n";
    }

    close(listen_fd);
#ifdef _WIN32
    WSACleanup();
#endif
}
