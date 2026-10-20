#include "JsonParser.h"

#include <cctype>
#include <charconv>
#include <cmath>

namespace {

constexpr std::size_t MAX_DEPTH = 32;
constexpr unsigned char FIRST_PRINTABLE = 0x20;

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    JsonValue parseDocument()
    {
        JsonValue root = parseValue();
        skipSpaces();
        if (pos_ != text_.size())
            fail("unexpected data after the end");
        return root;
    }

private:
    std::string_view text_;
    std::size_t pos_ = 0;
    std::size_t depth_ = 0;

    [[noreturn]] void fail(const std::string& what) const
    {
        throw JsonError("JSON error at offset " + std::to_string(pos_) + ": " + what);
    }

    bool atEnd() const { return pos_ >= text_.size(); }
    char peek() const { return atEnd() ? '\0' : text_[pos_]; }

    void skipSpaces()
    {
        while (!atEnd() && (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r'))
            ++pos_;
    }

    void expect(char c)
    {
        skipSpaces();
        if (peek() != c)
            fail(std::string("expected '") + c + "'");
        ++pos_;
    }

    bool consumeWord(std::string_view word)
    {
        if (text_.substr(pos_, word.size()) != word)
            return false;
        pos_ += word.size();
        return true;
    }

    JsonValue parseValue()
    {
        skipSpaces();
        if (atEnd())
            fail("unexpected end of input");

        switch (peek()) {
        case '{': return parseObject();
        case '[': return parseArray();
        case '"': return JsonValue(parseString());
        default: break;
        }
        if (consumeWord("true"))
            return JsonValue(true);
        if (consumeWord("false"))
            return JsonValue(false);
        if (consumeWord("null"))
            return JsonValue(nullptr);
        return JsonValue(parseNumber());
    }

    void enter()
    {
        if (++depth_ > MAX_DEPTH)
            fail("nesting too deep");
    }

    JsonValue parseObject()
    {
        enter();
        ++pos_;
        JsonValue::Object members;
        skipSpaces();
        if (peek() == '}') {
            ++pos_;
            --depth_;
            return JsonValue(std::move(members));
        }
        for (;;) {
            skipSpaces();
            if (peek() != '"')
                fail("expected a key");
            std::string key = parseString();
            for (const auto& [existing, value] : members)
                if (existing == key)
                    fail("duplicate key '" + key + "'");
            expect(':');
            members.emplace_back(std::move(key), parseValue());
            skipSpaces();
            if (peek() == ',') {
                ++pos_;
                continue;
            }
            expect('}');
            break;
        }
        --depth_;
        return JsonValue(std::move(members));
    }

    JsonValue parseArray()
    {
        enter();
        ++pos_;
        JsonValue::Array items;
        skipSpaces();
        if (peek() == ']') {
            ++pos_;
            --depth_;
            return JsonValue(std::move(items));
        }
        for (;;) {
            items.push_back(parseValue());
            skipSpaces();
            if (peek() == ',') {
                ++pos_;
                continue;
            }
            expect(']');
            break;
        }
        --depth_;
        return JsonValue(std::move(items));
    }

    std::string parseString()
    {
        ++pos_;
        std::string out;
        for (;;) {
            if (atEnd())
                fail("unterminated string");
            const char c = text_[pos_++];
            if (c == '"')
                return out;
            if (static_cast<unsigned char>(c) < FIRST_PRINTABLE)
                fail("control character in string");
            if (c == '\\' && (peek() == '"' || peek() == '\\' || peek() == '/')) {
                out.push_back(text_[pos_++]);
                continue;
            }
            out.push_back(c);
        }
    }

    double parseNumber()
    {
        const std::size_t start = pos_;
        if (peek() == '-')
            ++pos_;
        while (!atEnd() && (std::isdigit(static_cast<unsigned char>(peek())) || peek() == '.'
                            || peek() == 'e' || peek() == 'E' || peek() == '+' || peek() == '-'))
            ++pos_;

        double value = 0;
        const char* first = text_.data() + start;
        const char* last = text_.data() + pos_;
        const auto [end, ec] = std::from_chars(first, last, value);
        if (pos_ == start || ec != std::errc() || end != last || !std::isfinite(value))
            fail("invalid value");
        return value;
    }
};

}

const JsonValue* JsonValue::find(std::string_view key) const
{
    const Object* object = asObject();
    if (object == nullptr)
        return nullptr;
    for (const auto& [name, value] : *object)
        if (name == key)
            return &value;
    return nullptr;
}

JsonValue parseJson(std::string_view text)
{
    return Parser(text).parseDocument();
}
