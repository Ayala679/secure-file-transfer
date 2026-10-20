#include "Endian.h"
#include "TestFramework.h"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using Bytes = std::vector<std::uint8_t>;

TEST_CASE(u16_written_little_endian)
{
    Bytes out;
    endian::appendLE<std::uint16_t>(out, 825);
    CHECK((out == Bytes{0x39, 0x03}));
}

TEST_CASE(u32_written_little_endian)
{
    Bytes out;
    endian::appendLE<std::uint32_t>(out, 0x01020304);
    CHECK((out == Bytes{0x04, 0x03, 0x02, 0x01}));
}

TEST_CASE(u8_written_as_is)
{
    Bytes out;
    endian::appendLE<std::uint8_t>(out, 3);
    CHECK((out == Bytes{0x03}));
}

TEST_CASE(roundtrip_edge_values)
{
    for (std::uint32_t v : {0u, 1u, 0xFFFFu, 0x10000u, std::numeric_limits<std::uint32_t>::max()}) {
        Bytes out;
        endian::appendLE(out, v);
        CHECK(endian::readLE<std::uint32_t>(out, 0) == v);
    }
    for (std::uint16_t v : {std::uint16_t{0}, std::uint16_t{1600}, std::numeric_limits<std::uint16_t>::max()}) {
        Bytes out;
        endian::appendLE(out, v);
        CHECK(endian::readLE<std::uint16_t>(out, 0) == v);
    }
}

TEST_CASE(read_at_offset)
{
    const Bytes in{0xAA, 0x40, 0x06, 0xBB};
    CHECK(endian::readLE<std::uint16_t>(in, 1) == 1600);
}

TEST_CASE(read_past_end_throws)
{
    const Bytes in{0x01, 0x02, 0x03};
    CHECK_THROWS(endian::readLE<std::uint32_t>(in, 0), std::out_of_range);
    CHECK_THROWS(endian::readLE<std::uint16_t>(in, 2), std::out_of_range);
    CHECK_THROWS(endian::readLE<std::uint16_t>(in, 10), std::out_of_range);
}
