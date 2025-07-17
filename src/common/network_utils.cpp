#include "network_utils.h"
#include <pbc/pbc.h>
#include <arpa/inet.h>  // For inet_pton
#include <iostream>
#include <cstring>

// TCPServer implementation
TCPServer::TCPServer(int port) {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
}

void TCPServer::start() {
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);
}

int TCPServer::accept_connection() {
    int addrlen = sizeof(address);
    return accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
}

void TCPServer::send_data(int client_fd, const void* data, size_t len) {
    send(client_fd, &len, sizeof(size_t), 0);
    send(client_fd, data, len, 0);
}

void TCPServer::recv_data(int client_fd, void* buffer, size_t len) {
    recv(client_fd, &len, sizeof(size_t), 0);
    recv(client_fd, buffer, len, MSG_WAITALL);
}

void TCPServer::close_connection(int client_fd) {
    close(client_fd);
}

TCPServer::~TCPServer() {
    close(server_fd);
}

// TCPClient implementation
TCPClient::TCPClient(const char* ip, int port) {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv_addr.sin_addr);
}

void TCPClient::connect_to_server() {
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
}

void TCPClient::send_data(const void* data, size_t len) {
    send(sock, &len, sizeof(size_t), 0);
    send(sock, data, len, 0);
}

void TCPClient::recv_data(void* buffer, size_t len) {
    recv(sock, &len, sizeof(size_t), 0);
    recv(sock, buffer, len, MSG_WAITALL);
}

void TCPClient::close_connection() {
    close(sock);
}

TCPClient::~TCPClient() {
    close(sock);
}

// PBC element serialization

void send_element(int sock, element_t e) {
    // Use uncompressed serialization for reliability
    int len = element_length_in_bytes(e);
    if (len <= 0 || len > 4096) {
        std::cerr << "send_element: Invalid length " << len << std::endl;
        return;
    }

    unsigned char* buf = new unsigned char[len];
    element_to_bytes(buf, e);
    
    // Send length as uint32_t in network byte order
    uint32_t net_len = htonl(static_cast<uint32_t>(len));
    if (send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
        std::cerr << "send_element: Failed to send length" << std::endl;
        delete[] buf;
        return;
    }
    
    // Send data
    if (send(sock, buf, len, 0) != len) {
        std::cerr << "send_element: Failed to send data" << std::endl;
    }
    delete[] buf;
}

void recv_element(int sock, element_t e, pairing_ptr pairing) {
    uint32_t net_len;
    // Receive length
    if (recv(sock, &net_len, sizeof(net_len), MSG_WAITALL) != sizeof(net_len)) {
        std::cerr << "recv_element: Failed to receive length" << std::endl;
        return;
    }
    
    // Convert to host byte order
    uint32_t len = ntohl(net_len);
    if (len <= 0 || len > 4096) {
        std::cerr << "recv_element: Invalid length " << len << std::endl;
        return;
    }

    unsigned char* buf = new unsigned char[len];
    // Receive data
    ssize_t received = recv(sock, buf, len, MSG_WAITALL);
    if (received != static_cast<ssize_t>(len)) {
        std::cerr << "recv_element: Partial receive (" << received << "/" << len << ")" << std::endl;
        delete[] buf;
        return;
    }
    
    // Deserialize
    element_from_bytes(e, buf);
    std::cout << "Received element (" << len << " bytes)" << std::endl;
    delete[] buf;
}


