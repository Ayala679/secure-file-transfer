#include "Errors.h"
#include "TcpConnection.h"
#include "TestFramework.h"

#include <ws2tcpip.h>

#include <thread>

namespace {

constexpr unsigned SHORT_TIMEOUT_MS = 500;

class LoopbackListener {
public:
    LoopbackListener()
    {
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        listen(listener_, 1);
        int length = sizeof(address);
        getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length);
        port = ntohs(address.sin_port);
    }
    ~LoopbackListener() { closesocket(listener_); }

    SOCKET accept() const { return ::accept(listener_, nullptr, nullptr); }

    std::uint16_t port = 0;

private:
    WinsockSession winsock_;
    SOCKET listener_ = INVALID_SOCKET;
};

}

TEST_CASE(tcp_echo_roundtrip)
{
    LoopbackListener listener;
    std::thread server([&] {
        const SOCKET peer = listener.accept();
        char buffer[5];
        int got = 0;
        while (got < 5)
            got += recv(peer, buffer + got, 5 - got, 0);
        send(peer, buffer, 5, 0);
        closesocket(peer);
    });

    TcpConnection connection("127.0.0.1", listener.port, SHORT_TIMEOUT_MS * 4);
    const protocol::Bytes message{'h', 'e', 'l', 'l', 'o'};
    connection.sendAll(message);
    CHECK(connection.receiveExact(message.size()) == message);
    server.join();
}

TEST_CASE(tcp_peer_closes_early)
{
    LoopbackListener listener;
    std::thread server([&] { closesocket(listener.accept()); });
    TcpConnection connection("127.0.0.1", listener.port, SHORT_TIMEOUT_MS * 4);
    server.join();
    CHECK_THROWS(connection.receiveExact(1), FatalError);
}

TEST_CASE(tcp_receive_timeout)
{
    LoopbackListener listener;
    SOCKET peer = INVALID_SOCKET;
    std::thread server([&] { peer = listener.accept(); });
    TcpConnection connection("127.0.0.1", listener.port, SHORT_TIMEOUT_MS);
    server.join();
    CHECK_THROWS(connection.receiveExact(1), FatalError);
    closesocket(peer);
}

TEST_CASE(tcp_connection_refused)
{
    std::uint16_t freePort = 0;
    {
        LoopbackListener listener;
        freePort = listener.port;
    }
    CHECK_THROWS(TcpConnection("127.0.0.1", freePort, SHORT_TIMEOUT_MS), FatalError);
}

TEST_CASE(tcp_bad_address)
{
    CHECK_THROWS(TcpConnection("not-an-ip", 1234, SHORT_TIMEOUT_MS), FatalError);
}
