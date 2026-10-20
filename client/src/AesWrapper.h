#pragma once

#include "Protocol.h"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

#include <cstdint>

// AES-256-CBC, zero IV, PKCS#7 padding. Fed in chunks so big files never sit in memory.
class AesCbcEncryptor {
public:
    explicit AesCbcEncryptor(protocol::ByteView key);
    AesCbcEncryptor(const AesCbcEncryptor&) = delete;
    AesCbcEncryptor& operator=(const AesCbcEncryptor&) = delete;

    protocol::Bytes update(protocol::ByteView data);
    protocol::Bytes finish();

    static std::uint64_t encryptedSize(std::uint64_t plainSize);

private:
    protocol::Bytes takeOutput();

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cipher_;
    CryptoPP::StreamTransformationFilter filter_;
};
