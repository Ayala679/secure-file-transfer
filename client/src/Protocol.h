#pragma once

#include "Constants.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace protocol {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;
using ClientId = std::array<std::uint8_t, CLIENT_ID_SIZE>;

struct ResponseHeader {
    std::uint8_t version;
    std::uint16_t code;
    std::uint32_t payloadSize;
};

struct KeyResponse {
    ClientId clientId;
    Bytes encryptedAesKey;
};

struct FileReceived {
    ClientId clientId;
    std::uint32_t contentSize;
    std::string fileName;
    std::uint32_t cksum;
};

struct FilePacketInfo {
    std::uint32_t contentSize;
    std::uint32_t origSize;
    std::uint16_t packetNumber;
    std::uint16_t totalPackets;
    std::string_view fileName;
};

Bytes encodeName(std::string_view name);
std::string decodeName(ByteView field);

Bytes buildRequestHeader(const ClientId& clientId, RequestCode code, std::uint32_t payloadSize);
Bytes buildRequest(const ClientId& clientId, RequestCode code, ByteView payload);

Bytes namePayload(std::string_view name);
Bytes publicKeyPayload(std::string_view name, ByteView publicKey);
Bytes filePacketHeader(const FilePacketInfo& info);

struct PacketPlan {
    std::uint32_t packetSize;
    std::uint16_t totalPackets;
};

// throws std::length_error when the content does not fit the 4 byte size field
PacketPlan planPackets(std::uint64_t contentSize);

ResponseHeader parseResponseHeader(ByteView data);
ClientId parseClientId(ByteView payload);
KeyResponse parseKeyResponse(ByteView payload);
FileReceived parseFileReceived(ByteView payload);

}
