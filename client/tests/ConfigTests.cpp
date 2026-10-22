#include "Errors.h"
#include "JsonParser.h"
#include "TestFramework.h"
#include "TransferConfig.h"

#include <filesystem>
#include <fstream>
#include <string>

namespace {

constexpr const char* ASSIGNMENT_EXAMPLE = R"({
    "server": {
        "ip": "192.168.1.5",
        "port": 1265,
        "client": "MyComputer"
    },
    "files": [ "c:\doc\file02.docx",
               "c:\openu\defensive\file06-2026c.pdf"]
})";

std::string withServer(const std::string& serverBody, const std::string& files = R"(["a.bin"])")
{
    return R"({"server": {)" + serverBody + R"(}, "files": )" + files + "}";
}

}

TEST_CASE(json_basic_values)
{
    const JsonValue v = parseJson(R"({"a": [1, -2.5, true, null, "x\"y"], "b": {}})");
    const auto* a = v.find("a")->asArray();
    CHECK(a->size() == 5);
    CHECK(*(*a)[0].asNumber() == 1);
    CHECK(*(*a)[1].asNumber() == -2.5);
    CHECK(*(*a)[4].asString() == "x\"y");
    CHECK(v.find("b")->asObject()->empty());
    CHECK(v.find("missing") == nullptr);
}

TEST_CASE(json_backslashes_kept)
{
    const std::pair<const char*, const char*> cases[] = {
        {R"("c:\doc\file.txt")", R"(c:\doc\file.txt)"},
        {R"("c:\\doc\\new")", R"(c:\doc\new)"},
        {R"("c:\temp\b\n\r")", R"(c:\temp\b\n\r)"},
    };
    for (const auto& [json, expected] : cases) {
        const std::string parsed = *parseJson(json).asString();
        CHECK(parsed == expected);
    }
}

TEST_CASE(json_rejects_bad_input)
{
    for (const char* bad : {"", "{", R"({"a":})", R"({"a" 1})", "[1,]x", R"({"a":1,"a":2})",
                            "\"unterminated", "tru", "1.2.3", "{} {}", "\"tab\there\""}) {
        CHECK_THROWS(parseJson(bad), JsonError);
    }
}

TEST_CASE(json_depth_limited)
{
    CHECK_THROWS(parseJson(std::string(1000, '[') + std::string(1000, ']')), JsonError);
    CHECK(parseJson(std::string(10, '[') + std::string(10, ']')).asArray() != nullptr);
}

TEST_CASE(config_assignment_example)
{
    const auto config = TransferConfig::parse(ASSIGNMENT_EXAMPLE);
    CHECK(config.serverIp == "192.168.1.5");
    CHECK(config.port == 1265);
    CHECK(config.clientName == "MyComputer");
    CHECK(config.files.size() == 2);
    const std::filesystem::path firstFile = R"(c:\doc\file02.docx)";
    CHECK(config.files[0] == firstFile);
    CHECK(config.files[1].filename() == "file06-2026c.pdf");
}

TEST_CASE(config_client_at_top_level)
{
    const auto config = TransferConfig::parse(
        R"({"server": {"ip": "127.0.0.1", "port": 1234}, "client": "me", "files": ["x"]})");
    CHECK(config.clientName == "me");
}

TEST_CASE(config_invalid_values)
{
    const std::string name100(100, 'a');
    const std::string name101(101, 'a');
    const auto longest = TransferConfig::parse(
        withServer(R"("ip":"1.2.3.4","port":1,"client":")" + name100 + "\""));
    CHECK(longest.clientName.size() == 100);

    for (const std::string& bad : {
             withServer(R"("ip":"1.2.3.4","port":1234,"client":")" + name101 + "\""),
             withServer(R"("ip":"1.2.3.4","port":0,"client":"a")"),
             withServer(R"("ip":"1.2.3.4","port":70000,"client":"a")"),
             withServer(R"("ip":"1.2.3.4","port":12.5,"client":"a")"),
             withServer(R"("ip":"1.2.3.4","port":"1234","client":"a")"),
             withServer(R"("ip":"1.2.3","port":1234,"client":"a")"),
             withServer(R"("ip":"1.2.3.256","port":1234,"client":"a")"),
             withServer(R"("ip":"localhost","port":1234,"client":"a")"),
             withServer(R"("port":1234,"client":"a")"),
             withServer(R"("ip":"1.2.3.4","client":"a")"),
             withServer(R"("ip":"1.2.3.4","port":1234)"),
             withServer(R"("ip":"1.2.3.4","port":1234,"client":"")"),
             withServer(R"("ip":"1.2.3.4","port":1234,"client":"a")", "[]"),
             withServer(R"("ip":"1.2.3.4","port":1234,"client":"a")", "[\"\"]"),
             withServer(R"("ip":"1.2.3.4","port":1234,"client":"a")", "[5]"),
             std::string(R"({"files": ["a"]})"),
             std::string("[]"),
             std::string("not json"),
         }) {
        CHECK_THROWS(TransferConfig::parse(bad), FatalError);
    }
}

TEST_CASE(config_load_missing_file)
{
    CHECK_THROWS(TransferConfig::load("no_such_dir/transfer.json"), FatalError);
}

TEST_CASE(config_load_with_bom)
{
    const auto path = std::filesystem::temp_directory_path() / "transfer_bom_test.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << "\xEF\xBB\xBF" << withServer(R"("ip":"127.0.0.1","port":1234,"client":"bom")");
    }
    const auto config = TransferConfig::load(path);
    std::filesystem::remove(path);
    CHECK(config.clientName == "bom");
}
