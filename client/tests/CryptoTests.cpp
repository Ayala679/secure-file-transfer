#include "AesWrapper.h"
#include "Base64.h"
#include "Cksum.h"
#include "ClientIdentity.h"
#include "Constants.h"
#include "CryptoVectors.h"
#include "Errors.h"
#include "RsaWrapper.h"
#include "TestFramework.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

using protocol::Bytes;
namespace fs = std::filesystem;

namespace {

Bytes fromHex(std::string_view hex)
{
    Bytes out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
    return out;
}

Bytes pattern(std::size_t length)
{
    Bytes data(length);
    for (std::size_t i = 0; i < length; ++i)
        data[i] = static_cast<std::uint8_t>((i * 31 + 7) % 256);
    return data;
}

Bytes encryptInChunks(const Bytes& key, const Bytes& plain, std::size_t chunk)
{
    AesCbcEncryptor enc(key);
    Bytes out;
    for (std::size_t i = 0; i < plain.size(); i += chunk) {
        const auto part = enc.update(protocol::ByteView(plain).subspan(i, std::min(chunk, plain.size() - i)));
        out.insert(out.end(), part.begin(), part.end());
    }
    const auto last = enc.finish();
    out.insert(out.end(), last.begin(), last.end());
    return out;
}

struct TempDir {
    fs::path path = fs::temp_directory_path() / "client_identity_test";
    TempDir() { fs::create_directories(path); }
    ~TempDir() { fs::remove_all(path); }
    fs::path meInfo() const { return path / "me.info"; }
    fs::path privKey() const { return path / "priv.key"; }
    void write(const fs::path& file, const std::string& text) const { std::ofstream(file, std::ios::binary) << text; }
};

}

TEST_CASE(base64_known_values)
{
    const std::string foobar = "foobar";
    CHECK(base64::encode(Bytes(foobar.begin(), foobar.end())) == "Zm9vYmFy");
    CHECK(base64::encode(Bytes{'f'}) == "Zg==");
    CHECK((base64::decode("Zg==") == Bytes{'f'}));
    const Bytes data = pattern(1000);
    CHECK(base64::decode(base64::encode(data)) == data);
}

TEST_CASE(base64_rejects_garbage)
{
    for (const char* bad : {"", "Zg=", "Zg===", "Z===", "Zm9v!mFy", "Zm9v YmFy", "=Zg="})
        CHECK_THROWS(base64::decode(bad), std::invalid_argument);
}

TEST_CASE(rsa_python_key_loads_and_decrypts)
{
    const auto key = RsaPrivateKey::fromDer(fromHex(crypto_vectors::RSA_PRIVATE_KEY_DER));
    CHECK(key.publicKeyDer() == fromHex(crypto_vectors::RSA_PUBLIC_KEY_DER));
    CHECK(key.decrypt(fromHex(crypto_vectors::ENCRYPTED_AES_KEY)) == fromHex(crypto_vectors::AES_KEY));
}

TEST_CASE(rsa_generated_key_shape)
{
    const auto key = RsaPrivateKey::generate();
    CHECK(key.publicKeyDer().size() == protocol::PUBLIC_KEY_SIZE);
    const auto reloaded = RsaPrivateKey::fromDer(key.toDer());
    CHECK(reloaded.publicKeyDer() == key.publicKeyDer());
}

TEST_CASE(rsa_bad_inputs)
{
    CHECK_THROWS(RsaPrivateKey::fromDer(Bytes(100, 0x30)), FatalError);
    CHECK_THROWS(RsaPrivateKey::fromDer(fromHex(crypto_vectors::RSA_PUBLIC_KEY_DER)), FatalError);

    const auto key = RsaPrivateKey::fromDer(fromHex(crypto_vectors::RSA_PRIVATE_KEY_DER));
    CHECK_THROWS(key.decrypt(Bytes(127)), ProtocolError);
    CHECK_THROWS(key.decrypt(Bytes(crypto::RSA_CIPHERTEXT_SIZE, 0x42)), ProtocolError);
}

TEST_CASE(aes_matches_python)
{
    const Bytes key = fromHex(crypto_vectors::AES_KEY);
    for (const auto& v : crypto_vectors::AES_VECTORS) {
        const Bytes expected = fromHex(v.cipherHex);
        CHECK(encryptInChunks(key, pattern(v.length), 7) == expected);
        CHECK(expected.size() == AesCbcEncryptor::encryptedSize(v.length));
    }
}

TEST_CASE(aes_big_file_matches_python)
{
    const Bytes key = fromHex(crypto_vectors::AES_KEY);
    for (std::size_t chunk : {4096u, 65536u}) {
        const Bytes cipher = encryptInChunks(key, pattern(crypto_vectors::AES_BIG_LENGTH), chunk);
        CHECK(cipher.size() == crypto_vectors::AES_BIG_CIPHER_SIZE);
        Cksum crc;
        crc.update(cipher);
        CHECK(crc.digest() == crypto_vectors::AES_BIG_CIPHER_CKSUM);
    }
}

TEST_CASE(aes_rejects_bad_key)
{
    CHECK_THROWS(AesCbcEncryptor(Bytes(16)), std::invalid_argument);
}

TEST_CASE(identity_missing_is_nullopt)
{
    TempDir dir;
    CHECK(!ClientIdentity::load(dir.meInfo(), dir.privKey()).has_value());
}

TEST_CASE(identity_save_and_load)
{
    TempDir dir;
    ClientIdentity id;
    id.name = "Michael Jackson";
    for (std::size_t i = 0; i < id.clientId.size(); ++i)
        id.clientId[i] = static_cast<std::uint8_t>(0xF0 + i % 16);
    id.privateKeyBase64 = base64::encode(fromHex(crypto_vectors::RSA_PRIVATE_KEY_DER));
    id.save(dir.meInfo(), dir.privKey());

    const auto loaded = ClientIdentity::load(dir.meInfo(), dir.privKey());
    CHECK(loaded.has_value());
    CHECK(loaded->name == id.name);
    CHECK(loaded->clientId == id.clientId);
    CHECK(loaded->privateKeyBase64 == id.privateKeyBase64);

    std::ifstream in(dir.meInfo());
    std::string line1, line2;
    std::getline(in, line1);
    std::getline(in, line2);
    CHECK(line2 == "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
}

TEST_CASE(identity_falls_back_to_me_info_key)
{
    TempDir dir;
    dir.write(dir.meInfo(), "me\r\n000102030405060708090a0b0c0d0e0f\r\nZm9vYmFy\r\n");
    const auto loaded = ClientIdentity::load(dir.meInfo(), dir.privKey());
    CHECK(loaded->privateKeyBase64 == "Zm9vYmFy");
    CHECK(loaded->clientId[15] == 0x0f);
}

TEST_CASE(identity_corrupt_files)
{
    for (const char* content : {"", "only-name\n", "me\nnot-hex-not-hex-not-hex-not-he\nZm9v\n",
                                "me\n0001020304\nZm9v\n", "me\n000102030405060708090a0b0c0d0e0f\n",
                                "me\n000102030405060708090a0b0c0d0e0f\n!!!\n", "\n000102030405060708090a0b0c0d0e0f\nZm9v\n"}) {
        TempDir dir;
        dir.write(dir.meInfo(), content);
        CHECK_THROWS(ClientIdentity::load(dir.meInfo(), dir.privKey()), FatalError);
    }
}

TEST_CASE(identity_remove)
{
    TempDir dir;
    dir.write(dir.meInfo(), "x");
    dir.write(dir.privKey(), "y");
    ClientIdentity::remove(dir.meInfo(), dir.privKey());
    CHECK(!fs::exists(dir.meInfo()));
    CHECK(!fs::exists(dir.privKey()));
}
