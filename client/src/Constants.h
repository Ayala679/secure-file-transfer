#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace protocol {

inline constexpr std::uint8_t CLIENT_VERSION = 3;

inline constexpr std::size_t CLIENT_ID_SIZE = 16;
inline constexpr std::size_t VERSION_SIZE = 1;
inline constexpr std::size_t CODE_SIZE = 2;
inline constexpr std::size_t PAYLOAD_SIZE_FIELD_SIZE = 4;
inline constexpr std::size_t NAME_SIZE = 255;
inline constexpr std::size_t PUBLIC_KEY_SIZE = 160;
inline constexpr std::size_t CONTENT_SIZE_FIELD_SIZE = 4;
inline constexpr std::size_t ORIG_SIZE_FIELD_SIZE = 4;
inline constexpr std::size_t PACKET_NUMBER_SIZE = 2;
inline constexpr std::size_t TOTAL_PACKETS_SIZE = 2;
inline constexpr std::size_t CKSUM_SIZE = 4;

inline constexpr std::size_t REQUEST_HEADER_SIZE =
    CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD_SIZE;
inline constexpr std::size_t RESPONSE_HEADER_SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD_SIZE;
inline constexpr std::size_t PUBLIC_KEY_PAYLOAD_SIZE = NAME_SIZE + PUBLIC_KEY_SIZE;
inline constexpr std::size_t FILE_PACKET_HEADER_SIZE = CONTENT_SIZE_FIELD_SIZE + ORIG_SIZE_FIELD_SIZE
                                                     + PACKET_NUMBER_SIZE + TOTAL_PACKETS_SIZE + NAME_SIZE;
inline constexpr std::size_t FILE_RECEIVED_PAYLOAD_SIZE =
    CLIENT_ID_SIZE + CONTENT_SIZE_FIELD_SIZE + NAME_SIZE + CKSUM_SIZE;

inline constexpr std::size_t MAX_NAME_LENGTH = NAME_SIZE - 1;
inline constexpr std::size_t MAX_RESPONSE_PAYLOAD_SIZE = FILE_RECEIVED_PAYLOAD_SIZE;

enum class RequestCode : std::uint16_t {
    Register = 825,
    PublicKey = 826,
    Reconnect = 827,
    SendFile = 828,
    CrcOk = 900,
    CrcRetry = 901,
    CrcAbort = 902,
};

enum class ResponseCode : std::uint16_t {
    RegisterOk = 1600,
    RegisterFailed = 1601,
    AesKey = 1602,
    FileReceived = 1603,
    Ack = 1604,
    ReconnectOk = 1605,
    ReconnectDenied = 1606,
    GeneralError = 1607,
};

}

namespace crypto {

inline constexpr unsigned RSA_KEY_BITS = 1024;
inline constexpr std::size_t RSA_CIPHERTEXT_SIZE = RSA_KEY_BITS / 8;
inline constexpr std::size_t AES_KEY_SIZE = 32;
inline constexpr std::size_t AES_BLOCK_SIZE = 16;

}

namespace config {

inline constexpr std::string_view TRANSFER_FILE = "transfer.json";
inline constexpr std::string_view ME_FILE = "me.info";
inline constexpr std::string_view PRIVATE_KEY_FILE = "priv.key";

inline constexpr std::size_t MAX_CLIENT_NAME_LENGTH = 100;
inline constexpr std::size_t DEFAULT_PACKET_SIZE = 64 * 1024;
inline constexpr std::size_t MAX_PACKETS = 0xFFFF;

inline constexpr int MAX_SERVER_ERROR_RETRIES = 3;
inline constexpr int MAX_SEND_ATTEMPTS = 1 + 3;
inline constexpr unsigned RECEIVE_TIMEOUT_MS = 60 * 1000;

}
