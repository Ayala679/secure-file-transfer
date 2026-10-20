#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace endian {

inline constexpr unsigned BITS_PER_BYTE = 8;
inline constexpr unsigned BYTE_MASK = 0xFF;

// byte by byte, so the result does not depend on the CPU byte order
template <std::unsigned_integral T>
void appendLE(std::vector<std::uint8_t>& out, T value)
{
    for (std::size_t i = 0; i < sizeof(T); ++i)
        out.push_back(static_cast<std::uint8_t>((value >> (i * BITS_PER_BYTE)) & BYTE_MASK));
}

template <std::unsigned_integral T>
T readLE(std::span<const std::uint8_t> in, std::size_t offset)
{
    if (offset > in.size() || in.size() - offset < sizeof(T))
        throw std::out_of_range("read past end of buffer");

    T value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        value |= static_cast<T>(static_cast<T>(in[offset + i]) << (i * BITS_PER_BYTE));
    return value;
}

}
