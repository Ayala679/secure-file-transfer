#include "RsaWrapper.h"

#include "Constants.h"
#include "Errors.h"

#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>

namespace {

constexpr unsigned KEY_VALIDATION_LEVEL = 3;

protocol::Bytes drain(CryptoPP::ByteQueue& queue)
{
    protocol::Bytes out(static_cast<std::size_t>(queue.MaxRetrievable()));
    queue.Get(out.data(), out.size());
    return out;
}

}

RsaPrivateKey RsaPrivateKey::generate()
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey key;
    key.GenerateRandomWithKeySize(rng, crypto::RSA_KEY_BITS);
    return RsaPrivateKey(std::move(key));
}

RsaPrivateKey RsaPrivateKey::fromDer(protocol::ByteView der)
{
    CryptoPP::RSA::PrivateKey key;
    try {
        CryptoPP::ByteQueue queue;
        queue.Put(der.data(), der.size());
        queue.MessageEnd();
        key.Load(queue);
    } catch (const CryptoPP::Exception& e) {
        throw FatalError(std::string("cannot load private key: ") + e.what());
    }

    CryptoPP::AutoSeededRandomPool rng;
    if (key.GetModulus().BitCount() != crypto::RSA_KEY_BITS || !key.Validate(rng, KEY_VALIDATION_LEVEL))
        throw FatalError("private key is not a valid 1024 bit RSA key");
    return RsaPrivateKey(std::move(key));
}

protocol::Bytes RsaPrivateKey::toDer() const
{
    CryptoPP::ByteQueue queue;
    key_.Save(queue);
    return drain(queue);
}

protocol::Bytes RsaPrivateKey::publicKeyDer() const
{
    CryptoPP::ByteQueue queue;
    CryptoPP::RSA::PublicKey(key_).Save(queue);
    return drain(queue);
}

protocol::Bytes RsaPrivateKey::decrypt(protocol::ByteView ciphertext) const
{
    CryptoPP::AutoSeededRandomPool rng;
    const CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key_);
    if (ciphertext.size() != decryptor.FixedCiphertextLength())
        throw ProtocolError("encrypted key has wrong length");

    protocol::Bytes plain(decryptor.MaxPlaintextLength(ciphertext.size()));
    const auto result = decryptor.Decrypt(rng, ciphertext.data(), ciphertext.size(), plain.data());
    if (!result.isValidCoding)
        throw ProtocolError("cannot decrypt the AES key sent by the server");
    plain.resize(result.messageLength);
    return plain;
}
