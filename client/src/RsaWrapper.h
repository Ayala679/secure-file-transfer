#pragma once

#include "Protocol.h"

#include <cryptopp/rsa.h>

class RsaPrivateKey {
public:
    static RsaPrivateKey generate();
    static RsaPrivateKey fromDer(protocol::ByteView der);

    protocol::Bytes toDer() const;
    protocol::Bytes publicKeyDer() const;
    protocol::Bytes decrypt(protocol::ByteView ciphertext) const;

private:
    explicit RsaPrivateKey(CryptoPP::RSA::PrivateKey key) : key_(std::move(key)) {}
    CryptoPP::RSA::PrivateKey key_;
};
