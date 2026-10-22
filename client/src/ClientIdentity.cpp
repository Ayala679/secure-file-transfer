#include "ClientIdentity.h"

#include "Base64.h"
#include "Constants.h"
#include "Errors.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr std::size_t MAX_IDENTITY_FILE_SIZE = 16 * 1024;
constexpr std::size_t HEX_DIGITS_PER_BYTE = 2;
constexpr unsigned NIBBLE_BITS = 4;
constexpr unsigned NIBBLE_MASK = 0xF;
constexpr char HEX_DIGITS[] = "0123456789abcdef";
constexpr char FIRST_PRINTABLE = 0x20;
constexpr char LAST_PRINTABLE = 0x7E;

[[noreturn]] void corrupt(const std::string& what)
{
    throw FatalError(std::string(config::ME_FILE) + " is corrupt (" + what
                     + "). Fix it or delete it to register again");
}

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

std::vector<std::string> readLines(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw FatalError("cannot read " + path.filename().string());

    std::string content(MAX_IDENTITY_FILE_SIZE + 1, '\0');
    in.read(content.data(), static_cast<std::streamsize>(content.size()));
    content.resize(static_cast<std::size_t>(in.gcount()));
    if (content.size() > MAX_IDENTITY_FILE_SIZE)
        throw FatalError(path.filename().string() + " is too large");

    std::vector<std::string> lines;
    std::istringstream stream(content);
    for (std::string line; std::getline(stream, line);) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

bool isValidBase64(const std::string& text)
{
    try {
        base64::decode(text);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}

void writeFile(const fs::path& path, const std::string& content)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    out.close();
    if (!out)
        throw FatalError("cannot write " + path.filename().string());
}

}

std::string toHex(protocol::ByteView data)
{
    std::string out;
    out.reserve(data.size() * HEX_DIGITS_PER_BYTE);
    for (std::uint8_t b : data) {
        out.push_back(HEX_DIGITS[b >> NIBBLE_BITS]);
        out.push_back(HEX_DIGITS[b & NIBBLE_MASK]);
    }
    return out;
}

std::optional<ClientIdentity> ClientIdentity::load(const fs::path& meInfo, const fs::path& privateKey)
{
    std::error_code ec;
    if (!fs::exists(meInfo, ec))
        return std::nullopt;

    const auto lines = readLines(meInfo);
    if (lines.size() < 2)
        corrupt("expected name and id lines");

    ClientIdentity identity;
    identity.name = lines[0];
    if (identity.name.empty() || identity.name.size() > config::MAX_CLIENT_NAME_LENGTH
        || !std::all_of(identity.name.begin(), identity.name.end(),
                        [](char c) { return c >= FIRST_PRINTABLE && c <= LAST_PRINTABLE; }))
        corrupt("bad name");

    const std::string& hex = lines[1];
    if (hex.size() != protocol::CLIENT_ID_SIZE * HEX_DIGITS_PER_BYTE)
        corrupt("id must be 32 hex digits");
    for (std::size_t i = 0; i < protocol::CLIENT_ID_SIZE; ++i) {
        const int high = hexValue(hex[i * HEX_DIGITS_PER_BYTE]);
        const int low = hexValue(hex[i * HEX_DIGITS_PER_BYTE + 1]);
        if (high < 0 || low < 0)
            corrupt("id must be 32 hex digits");
        identity.clientId[i] = static_cast<std::uint8_t>((high << NIBBLE_BITS) | low);
    }

    if (fs::exists(privateKey, ec)) {
        const auto keyLines = readLines(privateKey);
        if (!keyLines.empty())
            identity.privateKeyBase64 = keyLines[0];
    }
    if (identity.privateKeyBase64.empty() && lines.size() >= 3)
        identity.privateKeyBase64 = lines[2];
    if (identity.privateKeyBase64.empty() || !isValidBase64(identity.privateKeyBase64))
        corrupt("missing or invalid private key");

    return identity;
}

void ClientIdentity::save(const fs::path& meInfo, const fs::path& privateKey) const
{
    writeFile(privateKey, privateKeyBase64 + "\n");
    writeFile(meInfo, name + "\n" + toHex(clientId) + "\n" + privateKeyBase64 + "\n");
}

void ClientIdentity::remove(const fs::path& meInfo, const fs::path& privateKey)
{
    std::error_code ec;
    fs::remove(meInfo, ec);
    fs::remove(privateKey, ec);
}
