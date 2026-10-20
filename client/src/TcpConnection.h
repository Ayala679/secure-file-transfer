#pragma once

#include "Protocol.h"

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

// Blocking TCP connection. Every failure is a FatalError: once the
// connection is broken there is nothing left to retry on.
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
