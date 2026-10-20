#pragma once

#include "Protocol.h"

#include <filesystem>
#include <optional>
#include <string>

// What the client remembers between runs: me.info and priv.key
struct ClientIdentity {
    std::string name;
    protocol::ClientId clientId{};
    std::string privateKeyBase64;

    // nullopt when me.info does not exist; FatalError when it is corrupt
    static std::optional<ClientIdentity> load(const std::filesystem::path& meInfo,
                                              const std::filesystem::path& privateKey);
    void save(const std::filesystem::path& meInfo, const std::filesystem::path& privateKey) const;
    static void remove(const std::filesystem::path& meInfo, const std::filesystem::path& privateKey);
};

std::string toHex(protocol::ByteView data);
