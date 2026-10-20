#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace base64 {

std::string encode(std::span<const std::uint8_t> data);

// throws std::invalid_argument on anything that is not clean base64
std::vector<std::uint8_t> decode(std::string_view text);

}
