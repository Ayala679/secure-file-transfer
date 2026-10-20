#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

// Same result as the POSIX/Linux cksum command
class Cksum {
public:
    void update(std::span<const std::uint8_t> data);
    std::uint32_t digest() const;

private:
    std::uint32_t crc_ = 0;
    std::uint64_t length_ = 0;
};
