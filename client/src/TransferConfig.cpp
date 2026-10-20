#include "TransferConfig.h"

#include "Constants.h"
#include "Errors.h"
#include "JsonParser.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iterator>
#include <limits>

namespace {

constexpr std::size_t MAX_CONFIG_FILE_SIZE = 64 * 1024;
constexpr int IPV4_PARTS = 4;
constexpr int MAX_OCTET = 255;
constexpr std::size_t MAX_OCTET_DIGITS = 3;
constexpr double MIN_PORT = 1;
constexpr double MAX_PORT = std::numeric_limits<std::uint16_t>::max();
constexpr char FIRST_PRINTABLE = 0x20;
constexpr char LAST_PRINTABLE = 0x7E;

[[noreturn]] void invalid(const std::string& what)
{
    throw FatalError(std::string(config::TRANSFER_FILE) + ": " + what);
}

bool isIpv4(std::string_view ip)
{
    int parts = 0;
    while (!ip.empty()) {
        const std::size_t dot = ip.find('.');
        const std::string_view part = ip.substr(0, dot);
        if (part.empty() || part.size() > MAX_OCTET_DIGITS
            || !std::all_of(part.begin(), part.end(), [](char c) { return c >= '0' && c <= '9'; })
            || std::stoi(std::string(part)) > MAX_OCTET)
            return false;
        ++parts;
        if (dot == std::string_view::npos)
            break;
        ip.remove_prefix(dot + 1);
        if (ip.empty())
            return false;
    }
    return parts == IPV4_PARTS;
}

const std::string& requireString(const JsonValue* value, const char* name)
{
    if (value == nullptr || value->asString() == nullptr)
        invalid(std::string("missing or non-string \"") + name + "\"");
    return *value->asString();
}

std::uint16_t requirePort(const JsonValue* value)
{
    if (value == nullptr || value->asNumber() == nullptr)
        invalid("missing or non-numeric \"port\"");
    const double port = *value->asNumber();
    if (port < MIN_PORT || port > MAX_PORT || std::floor(port) != port)
        invalid("\"port\" must be an integer between 1 and 65535");
    return static_cast<std::uint16_t>(port);
}

std::filesystem::path utf8Path(const std::string& text)
{
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

std::string displayPath(const std::filesystem::path& path)
{
    const std::u8string u8 = path.u8string();
    return std::string(u8.begin(), u8.end());
}

constexpr std::string_view UTF8_BOM = "\xEF\xBB\xBF";

}

TransferConfig TransferConfig::parse(std::string_view text)
{
    JsonValue root;
    try {
        root = parseJson(text);
    } catch (const JsonError& e) {
        invalid(e.what());
    }
    if (root.asObject() == nullptr)
        invalid("top level must be an object");

    const JsonValue* server = root.find("server");
    if (server == nullptr || server->asObject() == nullptr)
        invalid("missing \"server\" object");

    TransferConfig config;
    config.serverIp = requireString(server->find("ip"), "ip");
    if (!isIpv4(config.serverIp))
        invalid("\"ip\" must be an IPv4 address like 127.0.0.1");
    config.port = requirePort(server->find("port"));

    const JsonValue* client = server->find("client");
    config.clientName = requireString(client != nullptr ? client : root.find("client"), "client");
    const auto& name = config.clientName;
    if (name.empty() || name.size() > config::MAX_CLIENT_NAME_LENGTH
        || !std::all_of(name.begin(), name.end(),
                        [](char c) { return c >= FIRST_PRINTABLE && c <= LAST_PRINTABLE; }))
        invalid("\"client\" must be 1-" + std::to_string(config::MAX_CLIENT_NAME_LENGTH)
                + " printable ASCII characters");

    const JsonValue* files = root.find("files");
    if (files == nullptr || files->asArray() == nullptr || files->asArray()->empty())
        invalid("\"files\" must be a non-empty list");
    for (const JsonValue& entry : *files->asArray()) {
        const std::string* path = entry.asString();
        if (path == nullptr || path->empty())
            invalid("every entry in \"files\" must be a non-empty string");
        config.files.push_back(utf8Path(*path));
    }
    return config;
}

TransferConfig TransferConfig::load(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        invalid("cannot open " + displayPath(path));

    std::string text;
    text.resize(MAX_CONFIG_FILE_SIZE + 1);
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    text.resize(static_cast<std::size_t>(in.gcount()));
    if (text.size() > MAX_CONFIG_FILE_SIZE)
        invalid("file is too large");

    std::string_view content = text;
    if (content.starts_with(UTF8_BOM))
        content.remove_prefix(UTF8_BOM.size());
    return parse(content);
}
