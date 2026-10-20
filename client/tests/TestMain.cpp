#include "TestFramework.h"

#include <exception>
#include <iostream>

int main()
{
    int failed = 0;
    for (const auto& tc : test::registry()) {
        try {
            tc.body();
            std::cout << "  ok    " << tc.name << '\n';
        } catch (const test::Failure& f) {
            ++failed;
            std::cout << "  FAIL  " << tc.name << "\n        " << f.message << '\n';
        } catch (const std::exception& e) {
            ++failed;
            std::cout << "  FAIL  " << tc.name << "\n        unexpected exception: " << e.what() << '\n';
        }
    }
    std::cout << test::registry().size() << " tests, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}

TEST_CASE(framework_sanity)
{
    CHECK(!test::registry().empty());
}
