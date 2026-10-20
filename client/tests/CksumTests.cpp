#include "Cksum.h"
#include "ProtocolVectors.h"
#include "TestFramework.h"

#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> pattern(std::size_t length)
{
    std::vector<std::uint8_t> data(length);
    for (std::size_t i = 0; i < length; ++i)
        data[i] = static_cast<std::uint8_t>((i * 31 + 7) % 256);
    return data;
}

std::uint32_t cksumOf(std::span<const std::uint8_t> data)
{
    Cksum c;
    c.update(data);
    return c.digest();
}

}

TEST_CASE(cksum_known_values)
{
    CHECK(Cksum().digest() == 4294967295u);
    constexpr std::string_view check = "123456789";
    const std::vector<std::uint8_t> bytes(check.begin(), check.end());
    CHECK(cksumOf(bytes) == 930766865u);
}

TEST_CASE(cksum_matches_server)
{
    for (const auto& v : vectors::CKSUM_VECTORS)
        CHECK(cksumOf(pattern(v.length)) == v.cksum);
}

TEST_CASE(cksum_chunked_equals_whole)
{
    const auto data = pattern(100000);
    for (std::size_t chunk : {1u, 7u, 4096u, 65536u}) {
        Cksum c;
        for (std::size_t i = 0; i < data.size(); i += chunk)
            c.update(std::span(data).subspan(i, std::min(chunk, data.size() - i)));
        CHECK(c.digest() == cksumOf(data));
    }
}

TEST_CASE(cksum_digest_does_not_change_state)
{
    Cksum c;
    c.update(pattern(10));
    CHECK(c.digest() == c.digest());
}
