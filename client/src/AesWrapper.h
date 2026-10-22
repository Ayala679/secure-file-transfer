#pragma once

#include "Protocol.h"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

#include <cstdint>

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
