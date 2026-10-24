#include "TcpConnection.h"

#include "Errors.h"

#include <ws2tcpip.h>

#include <algorithm>
#include <climits>

#pragma comment(lib, "Ws2_32.lib")

namespace {

constexpr WORD WINSOCK_VERSION_REQUESTED = MAKEWORD(2, 2);
constexpr std::size_t MAX_IO_CHUNK = 64 * 1024;

std::string lastError(const std::string& what)
{
    return what + " (winsock error " + std::to_string(WSAGetLastError()) + ")";
}

}

WinsockSession::WinsockSession()
{
    WSADATA data{};
    if (WSAStartup(WINSOCK_VERSION_REQUESTED, &data) != 0)
        throw FatalError("cannot initialize winsock");
}

WinsockSession::~WinsockSession()
{
    WSACleanup();
}

TcpConnection::TcpConnection(const std::string& ip, std::uint16_t port, unsigned timeoutMs)
{
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1)
        throw FatalError("invalid server address " + ip);

    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET)
        throw FatalError(lastError("cannot create socket"));

    const DWORD timeout = timeoutMs;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    if (connect(socket_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        const std::string message = lastError("cannot connect to " + ip + ":" + std::to_string(port));
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        throw FatalError(message);
    }
}

TcpConnection::~TcpConnection()
{
    if (socket_ != INVALID_SOCKET) {
        shutdown(socket_, SD_BOTH);
        closesocket(socket_);
    }
}

void TcpConnection::sendAll(protocol::ByteView data)
{
    while (!data.empty()) {
        const int chunk = static_cast<int>((std::min)(data.size(), MAX_IO_CHUNK));
        const int sent = send(socket_, reinterpret_cast<const char*>(data.data()), chunk, 0);
        if (sent == SOCKET_ERROR || sent == 0)
            throw FatalError(lastError("connection to the server was lost while sending"));
        data = data.subspan(static_cast<std::size_t>(sent));
    }
}

protocol::Bytes TcpConnection::receiveExact(std::size_t size)
{
    protocol::Bytes buffer(size);
    std::size_t received = 0;
    while (received < size) {
        const int chunk = static_cast<int>((std::min)(size - received, MAX_IO_CHUNK));
        const int got = recv(socket_, reinterpret_cast<char*>(buffer.data() + received), chunk, 0);
        if (got == 0)
            throw FatalError("the server closed the connection");
        if (got == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAETIMEDOUT)
                throw FatalError("the server did not answer in time");
            throw FatalError(lastError("connection to the server was lost while receiving"));
        }
        received += static_cast<std::size_t>(got);
    }
    return buffer;
}
