#pragma once

#include "ClientIdentity.h"
#include "Protocol.h"
#include "RsaWrapper.h"
#include "TcpConnection.h"
#include "TransferConfig.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

class FileTransferClient {
public:
    FileTransferClient(TransferConfig config, const std::filesystem::path& baseDir);
    bool run();

private:
    struct Response {
        std::uint16_t code;
        protocol::Bytes payload;
    };

    struct OutgoingFile {
        std::filesystem::path path;
        std::string name;
        std::uint32_t origSize;
        std::uint32_t contentSize;
    };

    void connect();
    void reopenConnection();
    void send(protocol::RequestCode code, protocol::ByteView payload);
    Response receive();
    Response exchange(protocol::RequestCode code, protocol::ByteView payload);
    template <typename Attempt>
    auto withRetries(std::string_view action, Attempt attempt);

    protocol::Bytes establishKeys();
    std::optional<protocol::Bytes> reconnect(const ClientIdentity& identity);
    protocol::Bytes registerNew();
    protocol::Bytes takeAesKey(const RsaPrivateKey& key, const Response& response) const;

    bool sendFile(const std::filesystem::path& path);
    OutgoingFile prepare(const std::filesystem::path& path) const;
    std::uint32_t transmit(const OutgoingFile& file);
    std::uint32_t receiveServerCksum(const OutgoingFile& file);
    void confirm(protocol::RequestCode code, const OutgoingFile& file);

    TransferConfig config_;
    std::filesystem::path meInfoPath_;
    std::filesystem::path privateKeyPath_;
    std::unique_ptr<TcpConnection> connection_;
    protocol::ClientId clientId_{};
    std::string name_;
    protocol::Bytes aesKey_;
    bool keysEstablished_ = false;
};
