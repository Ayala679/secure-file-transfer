#include "Constants.h"
#include "Errors.h"
#include "FileTransferClient.h"
#include "TransferConfig.h"

#include <windows.h>

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

constexpr DWORD INITIAL_PATH_BUFFER = MAX_PATH;
constexpr DWORD MAX_PATH_BUFFER = 32 * 1024;

// transfer.json, me.info and priv.key live next to the exe, not in the working directory
std::filesystem::path executableDirectory()
{
    std::wstring buffer(INITIAL_PATH_BUFFER, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0)
            throw FatalError("cannot find the program location");
        if (length < buffer.size())
            return std::filesystem::path(buffer.substr(0, length)).parent_path();
        if (buffer.size() >= MAX_PATH_BUFFER)
            throw FatalError("program path is too long");
        buffer.resize(buffer.size() * 2);
    }
}

}

int main()
{
    try {
        std::cout << "file transfer client, version " << int{protocol::CLIENT_VERSION} << '\n';
        const auto baseDir = executableDirectory();
        auto config = TransferConfig::load(baseDir / config::TRANSFER_FILE);
        FileTransferClient client(std::move(config), baseDir);
        return client.run() ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const ClientError& e) {
        std::cerr << "Fatal: " << e.what() << '\n';
    } catch (const std::exception& e) {
        std::cerr << "Fatal: unexpected error: " << e.what() << '\n';
    }
    return EXIT_FAILURE;
}
