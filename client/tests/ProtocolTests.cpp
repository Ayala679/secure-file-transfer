#include "Constants.h"
#include "Errors.h"
#include "Protocol.h"
#include "ProtocolVectors.h"
#include "TestFramework.h"

#include <stdexcept>
#include <string>

using namespace protocol;

namespace {

Bytes fromHex(std::string_view hex)
{
    Bytes out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
    return out;
}

ClientId sampleId()
{
    ClientId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(i);
    return id;
}

Bytes samplePublicKey()
{
    Bytes key(PUBLIC_KEY_SIZE);
    for (std::size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<std::uint8_t>(i % 256);
    return key;
}

ByteView payloadOf(const Bytes& response)
{
    return ByteView(response).subspan(RESPONSE_HEADER_SIZE);
}

}

TEST_CASE(register_request_matches_server)
{
    CHECK(buildRequest(sampleId(), RequestCode::Register, namePayload("Ayala"))
          == fromHex(vectors::REGISTER_REQUEST));
}

TEST_CASE(public_key_request_matches_server)
{
    CHECK(buildRequest(sampleId(), RequestCode::PublicKey, publicKeyPayload("Ayala", samplePublicKey()))
          == fromHex(vectors::PUBLIC_KEY_REQUEST));
}

TEST_CASE(reconnect_request_matches_server)
{
    CHECK(buildRequest(sampleId(), RequestCode::Reconnect, namePayload("Ayala"))
          == fromHex(vectors::RECONNECT_REQUEST));
}

TEST_CASE(crc_ok_request_matches_server)
{
    CHECK(buildRequest(sampleId(), RequestCode::CrcOk, namePayload("data.bin"))
          == fromHex(vectors::CRC_OK_REQUEST));
}

TEST_CASE(file_packet_header_matches_server)
{
    const FilePacketInfo info{0x00019010, 102400, 1, 2, "data.bin"};
    CHECK(filePacketHeader(info) == fromHex(vectors::FILE_PACKET_HEADER));
}

TEST_CASE(parse_register_ok)
{
    const Bytes raw = fromHex(vectors::REGISTER_OK_RESPONSE);
    const auto header = parseResponseHeader(ByteView(raw).first(RESPONSE_HEADER_SIZE));
    CHECK(header.version == 3);
    CHECK(header.code == static_cast<std::uint16_t>(ResponseCode::RegisterOk));
    CHECK(header.payloadSize == CLIENT_ID_SIZE);
    CHECK(parseClientId(payloadOf(raw)) == sampleId());
}

TEST_CASE(parse_aes_key_response)
{
    const Bytes raw = fromHex(vectors::AES_KEY_RESPONSE);
    const auto response = parseKeyResponse(payloadOf(raw));
    CHECK(response.clientId == sampleId());
    CHECK(response.encryptedAesKey.size() == crypto::RSA_CIPHERTEXT_SIZE);
    CHECK(response.encryptedAesKey[1] == 7);
}

TEST_CASE(parse_file_received)
{
    const Bytes raw = fromHex(vectors::FILE_RECEIVED_RESPONSE);
    const auto header = parseResponseHeader(ByteView(raw).first(RESPONSE_HEADER_SIZE));
    CHECK(header.payloadSize == FILE_RECEIVED_PAYLOAD_SIZE);
    const auto result = parseFileReceived(payloadOf(raw));
    CHECK(result.clientId == sampleId());
    CHECK(result.contentSize == 0x00019010);
    CHECK(result.fileName == "data.bin");
    CHECK(result.cksum == 0xDEADBEEF);
}

TEST_CASE(parse_empty_error_response)
{
    const Bytes raw = fromHex(vectors::GENERAL_ERROR_RESPONSE);
    const auto header = parseResponseHeader(raw);
    CHECK(header.code == static_cast<std::uint16_t>(ResponseCode::GeneralError));
    CHECK(header.payloadSize == 0);
}

TEST_CASE(short_payloads_rejected)
{
    const Bytes raw = fromHex(vectors::FILE_RECEIVED_RESPONSE);
    const auto payload = payloadOf(raw);
    CHECK_THROWS(parseFileReceived(payload.first(payload.size() - 1)), ProtocolError);
    CHECK_THROWS(parseClientId(payload.first(CLIENT_ID_SIZE - 1)), ProtocolError);
    CHECK_THROWS(parseKeyResponse(payload.first(CLIENT_ID_SIZE)), ProtocolError);
    CHECK_THROWS(parseResponseHeader(ByteView(raw).first(RESPONSE_HEADER_SIZE - 1)), ProtocolError);
}

TEST_CASE(oversized_response_rejected)
{
    Bytes header = fromHex(vectors::GENERAL_ERROR_RESPONSE);
    header[3] = 0xFF;
    header[4] = 0xFF;
    CHECK_THROWS(parseResponseHeader(header), ProtocolError);
}

TEST_CASE(name_field_validation)
{
    CHECK(encodeName(std::string(MAX_NAME_LENGTH, 'a')).size() == NAME_SIZE);
    CHECK_THROWS(encodeName(""), std::invalid_argument);
    CHECK_THROWS(encodeName(std::string(NAME_SIZE, 'a')), std::invalid_argument);
    CHECK_THROWS(encodeName("bad\nname"), std::invalid_argument);

    Bytes noTerminator(NAME_SIZE, 'a');
    CHECK_THROWS(decodeName(noTerminator), ProtocolError);
    Bytes empty(NAME_SIZE, 0);
    CHECK_THROWS(decodeName(empty), ProtocolError);
    Bytes ok = encodeName("x.bin");
    ok[10] = 'z';
    CHECK(decodeName(ok) == "x.bin");
}

TEST_CASE(public_key_size_enforced)
{
    CHECK_THROWS(publicKeyPayload("Ayala", Bytes(PUBLIC_KEY_SIZE - 1)), std::invalid_argument);
}
