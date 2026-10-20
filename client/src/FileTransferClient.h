#pragma once

#include "ClientIdentity.h"
#include "Protocol.h"
#include "RsaWrapper.h"
#include "TcpConnection.h"
#include "TransferConfig.h"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

class FileTransferClient {
public:
    FileTransferClient(TransferConfig config, const std::filesystem::path& baseDir);
    void run();

private:
    struct Response {
        std::uint16_t code;
        protocol::Bytes payload;
    };

    void connect();
    Response exchange(protocol::RequestCode code, protocol::ByteView payload);
    template <typename Attempt>
    auto withRetries(std::string_view action, Attempt attempt);

    protocol::Bytes establishKeys();
    std::optional<protocol::Bytes> reconnect(const ClientIdentity& identity);
    protocol::Bytes registerNew();
    protocol::Bytes takeAesKey(const RsaPrivateKey& key, const Response& response) const;

    TransferConfig config_;
    std::filesystem::path meInfoPath_;
    std::filesystem::path privateKeyPath_;
    std::unique_ptr<TcpConnection> connection_;
    protocol::ClientId clientId_{};
    std::string name_;
};
