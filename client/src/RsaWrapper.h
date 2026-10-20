#pragma once

#include "Protocol.h"

#include <cryptopp/rsa.h>

class RsaPrivateKey {
public:
    static RsaPrivateKey generate();
    // throws FatalError when the key is not a valid 1024 bit RSA key
    static RsaPrivateKey fromDer(protocol::ByteView der);

    protocol::Bytes toDer() const;
    protocol::Bytes publicKeyDer() const;
    // RSA-OAEP with SHA-1, throws ProtocolError on bad ciphertext
    protocol::Bytes decrypt(protocol::ByteView ciphertext) const;

private:
    explicit RsaPrivateKey(CryptoPP::RSA::PrivateKey key) : key_(std::move(key)) {}
    CryptoPP::RSA::PrivateKey key_;
};
