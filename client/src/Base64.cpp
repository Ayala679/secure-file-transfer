#include "Base64.h"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include <algorithm>
#include <stdexcept>

namespace base64 {

namespace {

constexpr std::size_t QUANTUM = 4;
constexpr std::size_t MAX_PADDING = 2;
constexpr char PAD = '=';

bool isBase64Char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

}

std::string encode(std::span<const std::uint8_t> data)
{
    std::string out;
    const CryptoPP::StringSource source(data.data(), data.size(), true,
                                        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false));
    return out;
}

std::vector<std::uint8_t> decode(std::string_view text)
{
    if (text.empty() || text.size() % QUANTUM != 0)
        throw std::invalid_argument("base64 length must be a non-zero multiple of 4");
    const std::size_t padding = text.size() - text.find_last_not_of(PAD) - 1;
    if (padding > MAX_PADDING)
        throw std::invalid_argument("too much base64 padding");
    const std::string_view body = text.substr(0, text.size() - padding);
    if (!std::all_of(body.begin(), body.end(), isBase64Char))
        throw std::invalid_argument("invalid base64 character");

    std::string decoded;
    const CryptoPP::StringSource source(reinterpret_cast<const CryptoPP::byte*>(text.data()), text.size(), true,
                                        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    return {decoded.begin(), decoded.end()};
}

}
