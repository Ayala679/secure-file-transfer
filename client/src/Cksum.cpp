#include "Cksum.h"

#include <array>

namespace {

constexpr std::uint32_t CRC_POLY = 0x04C11DB7;
constexpr std::uint32_t TOP_BIT = 0x80000000;
constexpr unsigned BITS_PER_BYTE = 8;
constexpr unsigned TOP_BYTE_SHIFT = 24;
constexpr std::uint64_t BYTE_MASK = 0xFF;
constexpr std::size_t TABLE_SIZE = 256;

constexpr std::array<std::uint32_t, TABLE_SIZE> makeTable()
{
    std::array<std::uint32_t, TABLE_SIZE> table{};
    for (std::uint32_t i = 0; i < TABLE_SIZE; ++i) {
        std::uint32_t c = i << TOP_BYTE_SHIFT;
        for (unsigned bit = 0; bit < BITS_PER_BYTE; ++bit)
            c = (c & TOP_BIT) ? (c << 1) ^ CRC_POLY : (c << 1);
        table[i] = c;
    }
    return table;
}

constexpr auto TABLE = makeTable();

std::uint32_t feed(std::uint32_t crc, std::uint8_t byte)
{
    return (crc << BITS_PER_BYTE) ^ TABLE[((crc >> TOP_BYTE_SHIFT) ^ byte) & BYTE_MASK];
}

}

void Cksum::update(std::span<const std::uint8_t> data)
{
    for (std::uint8_t b : data)
        crc_ = feed(crc_, b);
    length_ += data.size();
}

std::uint32_t Cksum::digest() const
{
    // cksum appends the length, low byte first, with no leading zero bytes
    std::uint32_t crc = crc_;
    for (std::uint64_t n = length_; n != 0; n >>= BITS_PER_BYTE)
        crc = feed(crc, static_cast<std::uint8_t>(n & BYTE_MASK));
    return ~crc;
}
