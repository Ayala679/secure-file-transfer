#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

class JsonError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class JsonValue {
public:
    using Array = std::vector<JsonValue>;
    using Object = std::vector<std::pair<std::string, JsonValue>>;
    using Storage = std::variant<std::nullptr_t, bool, double, std::string, Array, Object>;

    JsonValue() = default;
    explicit JsonValue(Storage value) : value_(std::move(value)) {}

    const std::string* asString() const { return std::get_if<std::string>(&value_); }
    const double* asNumber() const { return std::get_if<double>(&value_); }
    const Array* asArray() const { return std::get_if<Array>(&value_); }
    const Object* asObject() const { return std::get_if<Object>(&value_); }

    const JsonValue* find(std::string_view key) const;

private:
    Storage value_;
};

// A small strict JSON reader for transfer.json.
// Windows paths are often written with single backslashes, so only \" \\ and \/
// are treated as escapes and any other backslash is kept as is.
JsonValue parseJson(std::string_view text);
