#include "Protocol.h"

#include "Endian.h"
#include "Errors.h"

#include <algorithm>
#include <stdexcept>

namespace protocol {

namespace {

constexpr char FIRST_PRINTABLE = 0x20;
constexpr char LAST_PRINTABLE = 0x7E;

bool isPrintableAscii(std::string_view text)
{
    return std::all_of(text.begin(), text.end(),
                       [](char c) { return c >= FIRST_PRINTABLE && c <= LAST_PRINTABLE; });
}

void requireSize(ByteView data, std::size_t expected, const char* what)
{
    if (data.size() != expected)
        throw ProtocolError(std::string(what) + ": expected " + std::to_string(expected) + " bytes, got "
                            + std::to_string(data.size()));
}

ClientId readClientId(ByteView data)
{
    ClientId id{};
    std::copy_n(data.begin(), CLIENT_ID_SIZE, id.begin());
    return id;
}

}

Bytes encodeName(std::string_view name)
{
    if (name.empty() || name.size() > MAX_NAME_LENGTH || !isPrintableAscii(name))
        throw std::invalid_argument("name must be 1-" + std::to_string(MAX_NAME_LENGTH)
                                    + " printable ASCII characters");
    Bytes field(NAME_SIZE, 0);
    std::copy(name.begin(), name.end(), field.begin());
    return field;
}

std::string decodeName(ByteView field)
{
    requireSize(field, NAME_SIZE, "name field");
    const auto end = std::find(field.begin(), field.end(), std::uint8_t{0});
    if (end == field.end())
        throw ProtocolError("name field is not null terminated");

    std::string name(field.begin(), end);
    if (name.empty() || !isPrintableAscii(name))
        throw ProtocolError("name field has invalid characters");
    return name;
}

Bytes buildRequestHeader(const ClientId& clientId, RequestCode code, std::uint32_t payloadSize)
{
    Bytes out(clientId.begin(), clientId.end());
    out.reserve(REQUEST_HEADER_SIZE);
    endian::appendLE(out, CLIENT_VERSION);
    endian::appendLE(out, static_cast<std::uint16_t>(code));
    endian::appendLE(out, payloadSize);
    return out;
}

Bytes buildRequest(const ClientId& clientId, RequestCode code, ByteView payload)
{
    if (payload.size() > UINT32_MAX)
        throw std::length_error("payload too large");
    Bytes out = buildRequestHeader(clientId, code, static_cast<std::uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Bytes namePayload(std::string_view name)
{
    return encodeName(name);
}

Bytes publicKeyPayload(std::string_view name, ByteView publicKey)
{
    if (publicKey.size() != PUBLIC_KEY_SIZE)
        throw std::invalid_argument("public key must be " + std::to_string(PUBLIC_KEY_SIZE) + " bytes");
    Bytes out = encodeName(name);
    out.insert(out.end(), publicKey.begin(), publicKey.end());
    return out;
}

Bytes filePacketHeader(const FilePacketInfo& info)
{
    Bytes out;
    out.reserve(FILE_PACKET_HEADER_SIZE);
    endian::appendLE(out, info.contentSize);
    endian::appendLE(out, info.origSize);
    endian::appendLE(out, info.packetNumber);
    endian::appendLE(out, info.totalPackets);
    const Bytes name = encodeName(info.fileName);
    out.insert(out.end(), name.begin(), name.end());
    return out;
}

ResponseHeader parseResponseHeader(ByteView data)
{
    requireSize(data, RESPONSE_HEADER_SIZE, "response header");
    ResponseHeader header{};
    std::size_t offset = 0;
    header.version = endian::readLE<std::uint8_t>(data, offset);
    offset += VERSION_SIZE;
    header.code = endian::readLE<std::uint16_t>(data, offset);
    offset += CODE_SIZE;
    header.payloadSize = endian::readLE<std::uint32_t>(data, offset);

    if (header.payloadSize > MAX_RESPONSE_PAYLOAD_SIZE)
        throw ProtocolError("response payload too large: " + std::to_string(header.payloadSize));
    return header;
}

ClientId parseClientId(ByteView payload)
{
    requireSize(payload, CLIENT_ID_SIZE, "client id payload");
    return readClientId(payload);
}

KeyResponse parseKeyResponse(ByteView payload)
{
    requireSize(payload, CLIENT_ID_SIZE + crypto::RSA_CIPHERTEXT_SIZE, "key payload");
    const auto key = payload.subspan(CLIENT_ID_SIZE);
    return {readClientId(payload), Bytes(key.begin(), key.end())};
}

FileReceived parseFileReceived(ByteView payload)
{
    requireSize(payload, FILE_RECEIVED_PAYLOAD_SIZE, "file received payload");
    FileReceived result{};
    std::size_t offset = 0;
    result.clientId = readClientId(payload);
    offset += CLIENT_ID_SIZE;
    result.contentSize = endian::readLE<std::uint32_t>(payload, offset);
    offset += CONTENT_SIZE_FIELD_SIZE;
    result.fileName = decodeName(payload.subspan(offset, NAME_SIZE));
    offset += NAME_SIZE;
    result.cksum = endian::readLE<std::uint32_t>(payload, offset);
    return result;
}

}
