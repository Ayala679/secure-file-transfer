#pragma once

#include "Protocol.h"

#include <filesystem>
#include <optional>
#include <string>

struct ClientIdentity {
    std::string name;
    protocol::ClientId clientId{};
    std::string privateKeyBase64;

    static std::optional<ClientIdentity> load(const std::filesystem::path& meInfo,
                                              const std::filesystem::path& privateKey);
    void save(const std::filesystem::path& meInfo, const std::filesystem::path& privateKey) const;
    static void remove(const std::filesystem::path& meInfo, const std::filesystem::path& privateKey);
};

std::string toHex(protocol::ByteView data);
