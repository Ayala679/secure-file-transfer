#include "FileTransferClient.h"

#include "AesWrapper.h"
#include "Base64.h"
#include "Cksum.h"
#include "Constants.h"
#include "Errors.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <system_error>

using protocol::Bytes;
using protocol::RequestCode;
using protocol::ResponseCode;

namespace {

constexpr std::string_view SERVER_ERROR_MESSAGE = "server responded with an error";
constexpr char FIRST_PRINTABLE = 0x20;
constexpr char LAST_PRINTABLE = 0x7E;

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

std::string displayPath(const std::filesystem::path& path)
{
    const std::u8string u8 = path.u8string();
    return std::string(u8.begin(), u8.end());
}

}

FileTransferClient::FileTransferClient(TransferConfig config, const std::filesystem::path& baseDir)
    : config_(std::move(config)),
      meInfoPath_(baseDir / config::ME_FILE),
      privateKeyPath_(baseDir / config::PRIVATE_KEY_FILE)
{
}

bool FileTransferClient::run()
{
    connect();
    aesKey_ = establishKeys();

    std::size_t verified = 0;
    for (const auto& path : config_.files) {
        try {
            if (sendFile(path))
                ++verified;
        } catch (const FileError& e) {
            std::cerr << "skipping " << displayPath(path) << ": " << e.what() << '\n';
        }
    }
    std::cout << verified << " of " << config_.files.size() << " file(s) sent and verified\n";
    return verified == config_.files.size();
}

void FileTransferClient::connect()
{
    std::cout << "connecting to " << config_.serverIp << ':' << config_.port << '\n';
    connection_.reset();
    connection_ = std::make_unique<TcpConnection>(config_.serverIp, config_.port, config::RECEIVE_TIMEOUT_MS);
}

void FileTransferClient::send(RequestCode code, protocol::ByteView payload)
{
    connection_->sendAll(protocol::buildRequest(clientId_, code, payload));
}

FileTransferClient::Response FileTransferClient::receive()
{
    const Bytes rawHeader = connection_->receiveExact(protocol::RESPONSE_HEADER_SIZE);
    const auto header = protocol::parseResponseHeader(rawHeader);
    if (header.version != protocol::CLIENT_VERSION)
        std::cerr << "warning: server version " << int{header.version} << '\n';
    return {header.code, connection_->receiveExact(header.payloadSize)};
}

FileTransferClient::Response FileTransferClient::exchange(RequestCode code, protocol::ByteView payload)
{
    send(code, payload);
    return receive();
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
    const auto key = [&] {
        try {
            return RsaPrivateKey::fromDer(base64::decode(identity.privateKeyBase64));
        } catch (const FatalError& e) {
            throw FatalError(std::string("the saved private key is unusable (") + e.what() + "). Delete "
                             + std::string(config::ME_FILE) + " and " + std::string(config::PRIVATE_KEY_FILE)
                             + " to register again");
        }
    }();
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

// Sends one file and checks the server's cksum: up to MAX_SEND_ATTEMPTS sends,
// 901 between them and 902 when the last one still does not match.
bool FileTransferClient::sendFile(const std::filesystem::path& path)
{
    const OutgoingFile file = prepare(path);
    std::cout << "sending '" << file.name << "' (" << file.origSize << " bytes)\n";

    for (int attempt = 1; attempt <= config::MAX_SEND_ATTEMPTS; ++attempt) {
        const auto [localCksum, serverCksum] = withRetries("send " + file.name, [&] {
            const std::uint32_t local = transmit(file);
            return std::pair{local, receiveServerCksum(file)};
        });
        std::cout << "  cksum: local " << localCksum << ", server " << serverCksum << '\n';

        if (localCksum == serverCksum) {
            confirm(RequestCode::CrcOk, file);
            std::cout << "  '" << file.name << "' verified\n";
            return true;
        }
        if (attempt < config::MAX_SEND_ATTEMPTS) {
            std::cout << "  cksum mismatch, sending again (attempt " << attempt + 1 << " of "
                      << config::MAX_SEND_ATTEMPTS << ")\n";
            send(RequestCode::CrcRetry, protocol::namePayload(file.name));
        }
    }
    confirm(RequestCode::CrcAbort, file);
    std::cout << "  giving up on '" << file.name << "' after " << config::MAX_SEND_ATTEMPTS << " attempts\n";
    return false;
}

FileTransferClient::OutgoingFile FileTransferClient::prepare(const std::filesystem::path& path) const
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
        throw FileError("file not found");
    const std::uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec)
        throw FileError("cannot read the file size");
    const std::uint64_t contentSize = AesCbcEncryptor::encryptedSize(size);
    if (contentSize > UINT32_MAX)
        throw FileError("file is too large for the protocol (4 GB limit)");

    const std::u8string u8name = path.filename().u8string();
    std::string name(u8name.begin(), u8name.end());
    if (name.empty() || name.size() > protocol::MAX_NAME_LENGTH
        || !std::all_of(name.begin(), name.end(), [](char c) { return c >= FIRST_PRINTABLE && c <= LAST_PRINTABLE; }))
        throw FileError("file name must be up to " + std::to_string(protocol::MAX_NAME_LENGTH)
                        + " printable ASCII characters");

    return {path, std::move(name), static_cast<std::uint32_t>(size), static_cast<std::uint32_t>(contentSize)};
}

// Streams the file: read, cksum, encrypt and send packet by packet,
// so the whole file is never held in memory. Returns the local cksum.
std::uint32_t FileTransferClient::transmit(const OutgoingFile& file)
{
    std::ifstream in(file.path, std::ios::binary);
    if (!in)
        throw FileError("cannot open the file");

    const auto plan = protocol::planPackets(file.contentSize);
    AesCbcEncryptor encryptor(aesKey_);
    Cksum cksum;
    Bytes pending;
    Bytes readBuffer(config::FILE_READ_CHUNK);
    std::uint64_t bytesRead = 0;
    std::uint16_t packetNumber = 0;

    auto sendPacket = [&](std::size_t length) {
        ++packetNumber;
        const protocol::FilePacketInfo info{file.contentSize, file.origSize, packetNumber, plan.totalPackets,
                                            file.name};
        const Bytes packetHeader = protocol::filePacketHeader(info);
        const auto payloadSize = static_cast<std::uint32_t>(packetHeader.size() + length);
        connection_->sendAll(protocol::buildRequestHeader(clientId_, RequestCode::SendFile, payloadSize));
        connection_->sendAll(packetHeader);
        connection_->sendAll(protocol::ByteView(pending).first(length));
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(length));
    };
    auto append = [&](const Bytes& data) {
        pending.insert(pending.end(), data.begin(), data.end());
        while (pending.size() >= plan.packetSize && packetNumber + 1 < plan.totalPackets)
            sendPacket(plan.packetSize);
    };

    while (in) {
        in.read(reinterpret_cast<char*>(readBuffer.data()), static_cast<std::streamsize>(readBuffer.size()));
        const auto got = static_cast<std::size_t>(in.gcount());
        if (got == 0)
            break;
        const protocol::ByteView chunk(readBuffer.data(), got);
        bytesRead += got;
        cksum.update(chunk);
        append(encryptor.update(chunk));
    }
    append(encryptor.finish());

    // the file changed while we were reading it; the server is now out of sync
    if (bytesRead != file.origSize || pending.size() > plan.packetSize)
        throw FatalError("'" + file.name + "' changed while it was being sent");
    sendPacket(pending.size());
    if (packetNumber != plan.totalPackets)
        throw FatalError("internal error: sent " + std::to_string(packetNumber) + " of "
                         + std::to_string(plan.totalPackets) + " packets");
    return cksum.digest();
}

std::uint32_t FileTransferClient::receiveServerCksum(const OutgoingFile& file)
{
    const auto response = receive();
    expectCode(response.code, ResponseCode::FileReceived);
    const auto received = protocol::parseFileReceived(response.payload);
    if (received.clientId != clientId_ || received.fileName != file.name
        || received.contentSize != file.contentSize)
        throw ProtocolError("file confirmation does not match the file that was sent");
    return received.cksum;
}

void FileTransferClient::confirm(RequestCode code, const OutgoingFile& file)
{
    withRetries("confirm " + file.name, [&] {
        const auto response = exchange(code, protocol::namePayload(file.name));
        expectCode(response.code, ResponseCode::Ack);
        if (protocol::parseClientId(response.payload) != clientId_)
            throw ProtocolError("acknowledgement is for a different client id");
    });
}
