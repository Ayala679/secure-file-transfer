#pragma once

#include "Protocol.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <cstdint>
#include <string>

class WinsockSession {
public:
    WinsockSession();
    ~WinsockSession();
    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;
};

class TcpConnection {
public:
    TcpConnection(const std::string& ip, std::uint16_t port, unsigned timeoutMs);
    ~TcpConnection();
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    void sendAll(protocol::ByteView data);
    protocol::Bytes receiveExact(std::size_t size);

private:
    WinsockSession winsock_;
    SOCKET socket_ = INVALID_SOCKET;
};
