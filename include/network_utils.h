#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <pbc/pbc.h>

class TCPServer {
public:
    TCPServer(int port);
    void start();
    int accept_connection();
    void send_data(int client_fd, const void* data, size_t len);
    void recv_data(int client_fd, void* buffer, size_t len);
    void close_connection(int client_fd);
    ~TCPServer();
private:
    int server_fd;
    struct sockaddr_in address;
};

class TCPClient {
public:
    TCPClient(const char* ip, int port);
    void connect_to_server();
    void send_data(const void* data, size_t len);
    void recv_data(void* buffer, size_t len);
    void close_connection();
    ~TCPClient();
    int get_sock() const { return sock; }
private:
    int sock;
    struct sockaddr_in serv_addr;
};

void send_element(int sock, element_t e);
void recv_element(int sock, element_t e, pairing_ptr pairing);
#endif // NETWORK_UTILS_H
