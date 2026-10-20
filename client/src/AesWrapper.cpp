#include "AesWrapper.h"

#include "Constants.h"

#include <array>
#include <stdexcept>

namespace {

const std::array<CryptoPP::byte, crypto::AES_BLOCK_SIZE> ZERO_IV{};

}

AesCbcEncryptor::AesCbcEncryptor(protocol::ByteView key)
    : filter_(cipher_, nullptr, CryptoPP::StreamTransformationFilter::PKCS_PADDING)
{
    if (key.size() != crypto::AES_KEY_SIZE)
        throw std::invalid_argument("AES key must be 32 bytes");
    cipher_.SetKeyWithIV(key.data(), key.size(), ZERO_IV.data(), ZERO_IV.size());
}

protocol::Bytes AesCbcEncryptor::update(protocol::ByteView data)
{
    filter_.Put(data.data(), data.size());
    return takeOutput();
}

protocol::Bytes AesCbcEncryptor::finish()
{
    filter_.MessageEnd();
    return takeOutput();
}

protocol::Bytes AesCbcEncryptor::takeOutput()
{
    protocol::Bytes out(static_cast<std::size_t>(filter_.MaxRetrievable()));
    filter_.Get(out.data(), out.size());
    return out;
}

std::uint64_t AesCbcEncryptor::encryptedSize(std::uint64_t plainSize)
{
    return (plainSize / crypto::AES_BLOCK_SIZE + 1) * crypto::AES_BLOCK_SIZE;
}
