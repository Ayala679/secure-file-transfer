#include "FileTransferClient.h"

#include "Base64.h"
#include "Constants.h"
#include "Errors.h"
#include "RsaWrapper.h"

#include <iostream>

using protocol::Bytes;
using protocol::RequestCode;
using protocol::ResponseCode;

namespace {

constexpr std::string_view SERVER_ERROR_MESSAGE = "server responded with an error";

std::uint16_t codeOf(ResponseCode code)
{
    return static_cast<std::uint16_t>(code);
}

void expectCode(std::uint16_t actual, ResponseCode expected)
{
    if (actual == codeOf(expected))
        return;
    if (actual == codeOf(ResponseCode::GeneralError))
        throw ServerError("general server error (1607)");
    if (actual == codeOf(ResponseCode::RegisterFailed))
        throw ServerError("registration failed (1601), the name may already be taken");
    throw ServerError("unexpected response code " + std::to_string(actual) + ", expected "
                      + std::to_string(codeOf(expected)));
}

}

FileTransferClient::FileTransferClient(TransferConfig config, const std::filesystem::path& baseDir)
    : config_(std::move(config)),
      meInfoPath_(baseDir / config::ME_FILE),
      privateKeyPath_(baseDir / config::PRIVATE_KEY_FILE)
{
}

void FileTransferClient::run()
{
    connect();
    const Bytes aesKey = establishKeys();
    std::cout << "AES key received, " << config_.files.size() << " file(s) to send\n";
}

void FileTransferClient::connect()
{
    std::cout << "connecting to " << config_.serverIp << ':' << config_.port << '\n';
    connection_.reset();
    connection_ = std::make_unique<TcpConnection>(config_.serverIp, config_.port, config::RECEIVE_TIMEOUT_MS);
}

FileTransferClient::Response FileTransferClient::exchange(RequestCode code, protocol::ByteView payload)
{
    connection_->sendAll(protocol::buildRequest(clientId_, code, payload));

    const Bytes rawHeader = connection_->receiveExact(protocol::RESPONSE_HEADER_SIZE);
    const auto header = protocol::parseResponseHeader(rawHeader);
    if (header.version != protocol::CLIENT_VERSION)
        std::cerr << "warning: server version " << int{header.version} << '\n';
    return {header.code, connection_->receiveExact(header.payloadSize)};
}

// Runs one request step; on a server error it prints the required message
// and tries again, up to MAX_SERVER_ERROR_RETRIES more times.
template <typename Attempt>
auto FileTransferClient::withRetries(std::string_view action, Attempt attempt)
{
    for (int retry = 0;; ++retry) {
        try {
            return attempt();
        } catch (const ServerError& e) {
            std::cout << SERVER_ERROR_MESSAGE << '\n';
            std::cerr << "  " << action << ": " << e.what() << '\n';
            if (retry == config::MAX_SERVER_ERROR_RETRIES)
                throw FatalError(std::string(action) + " failed after "
                                 + std::to_string(config::MAX_SERVER_ERROR_RETRIES + 1) + " attempts: " + e.what());
            if (dynamic_cast<const ProtocolError*>(&e) != nullptr)
                connect();
        }
    }
}

Bytes FileTransferClient::establishKeys()
{
    if (auto identity = ClientIdentity::load(meInfoPath_, privateKeyPath_)) {
        if (auto aesKey = reconnect(*identity))
            return *aesKey;
        std::cout << "server rejected the reconnect, registering as a new client\n";
        ClientIdentity::remove(meInfoPath_, privateKeyPath_);
        clientId_ = {};
    }
    return registerNew();
}

std::optional<Bytes> FileTransferClient::reconnect(const ClientIdentity& identity)
{
    name_ = identity.name;
    clientId_ = identity.clientId;
    const auto key = RsaPrivateKey::fromDer(base64::decode(identity.privateKeyBase64));
    std::cout << "found " << config::ME_FILE << ", reconnecting as '" << name_ << "' (" << toHex(clientId_)
              << ")\n";

    return withRetries("reconnect", [&]() -> std::optional<Bytes> {
        const auto response = exchange(RequestCode::Reconnect, protocol::namePayload(name_));
        if (response.code == codeOf(ResponseCode::ReconnectDenied))
            return std::nullopt;
        expectCode(response.code, ResponseCode::ReconnectOk);
        std::cout << "reconnected, got a new AES key\n";
        return takeAesKey(key, response);
    });
}

Bytes FileTransferClient::registerNew()
{
    name_ = config_.clientName;
    std::cout << "registering as '" << name_ << "'\n";
    clientId_ = withRetries("register", [&] {
        const auto response = exchange(RequestCode::Register, protocol::namePayload(name_));
        expectCode(response.code, ResponseCode::RegisterOk);
        return protocol::parseClientId(response.payload);
    });
    std::cout << "registered, client id " << toHex(clientId_) << '\n';

    const auto key = RsaPrivateKey::generate();
    ClientIdentity{name_, clientId_, base64::encode(key.toDer())}.save(meInfoPath_, privateKeyPath_);
    std::cout << "generated RSA key pair, saved " << config::ME_FILE << " and " << config::PRIVATE_KEY_FILE << '\n';

    const Bytes publicKey = key.publicKeyDer();
    return withRetries("send public key", [&] {
        const auto response = exchange(RequestCode::PublicKey, protocol::publicKeyPayload(name_, publicKey));
        expectCode(response.code, ResponseCode::AesKey);
        std::cout << "public key accepted, got the AES key\n";
        return takeAesKey(key, response);
    });
}

Bytes FileTransferClient::takeAesKey(const RsaPrivateKey& key, const Response& response) const
{
    const auto parsed = protocol::parseKeyResponse(response.payload);
    if (parsed.clientId != clientId_)
        throw ProtocolError("key response is for a different client id");
    Bytes aesKey = key.decrypt(parsed.encryptedAesKey);
    if (aesKey.size() != crypto::AES_KEY_SIZE)
        throw ProtocolError("AES key has the wrong size");
    return aesKey;
}
