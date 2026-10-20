#pragma once

#include <functional>
#include <string>
#include <vector>

namespace test {

struct TestCase {
    const char* name;
    std::function<void()> body;
};

struct Failure {
    std::string message;
};

inline std::vector<TestCase>& registry()
{
    static std::vector<TestCase> cases;
    return cases;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> body)
    {
        registry().push_back({name, std::move(body)});
    }
};

inline std::string where(const char* file, int line)
{
    return std::string(file) + ":" + std::to_string(line);
}

}

#define TEST_CASE(name)                                       \
    static void name();                                       \
    static const test::Registrar name##_registrar(#name, name); \
    static void name()

#define CHECK(expr)                                                              \
    do {                                                                         \
        if (!(expr))                                                             \
            throw test::Failure{test::where(__FILE__, __LINE__) + "  CHECK(" #expr ")"}; \
    } while (0)

#define CHECK_THROWS(expr, ExceptionType)                                        \
    do {                                                                         \
        bool thrown_ = false;                                                    \
        try {                                                                    \
            expr;                                                                \
        } catch (const ExceptionType&) {                                         \
            thrown_ = true;                                                      \
        }                                                                        \
        if (!thrown_)                                                            \
            throw test::Failure{test::where(__FILE__, __LINE__) +                \
                                "  expected " #ExceptionType " from " #expr};    \
    } while (0)
