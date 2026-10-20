#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

struct TransferConfig {
    std::string serverIp;
    std::uint16_t port = 0;
    std::string clientName;
    std::vector<std::filesystem::path> files;

    static TransferConfig load(const std::filesystem::path& path);
    static TransferConfig parse(std::string_view text);
};
