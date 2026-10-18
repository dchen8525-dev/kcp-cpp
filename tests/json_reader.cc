// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors

#include "json_reader.h"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace kcp {
namespace test {
namespace {

class Parser {
 public:
  Parser(const std::string& text) : text_(text) {}

  bool Parse(JsonValue* out, std::string* error) {
    SkipSpace();
    if (!ParseValue(out)) {
      if (error != nullptr) {
        *error = "at offset " + std::to_string(pos_) + ": " + error_;
      }
      return false;
    }
    SkipSpace();
    if (pos_ != text_.size()) {
      if (error != nullptr) {
        *error = "trailing data at offset " + std::to_string(pos_);
      }
      return false;
    }
    return true;
  }

 private:
  void SkipSpace() {
    while (pos_ < text_.size()) {
      const char c = text_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos_;
      } else {
        break;
      }
    }
  }

  bool Fail(const std::string& message) {
    if (error_.empty()) {
      error_ = message;
    }
    return false;
  }

  bool Consume(char expected) {
    if (pos_ < text_.size() && text_[pos_] == expected) {
      ++pos_;
      return true;
    }
    return Fail(std::string("expected '") + expected + "'");
  }

  bool ParseValue(JsonValue* out) {
    SkipSpace();
    if (pos_ >= text_.size()) {
      return Fail("unexpected end of input");
    }
    const char c = text_[pos_];
    if (c == '{') {
      return ParseObject(out);
    }
    if (c == '[') {
      return ParseArray(out);
    }
    if (c == '"') {
      out->type = JsonValue::Type::kString;
      return ParseString(&out->string_value);
    }
    if (c == 't' || c == 'f') {
      return ParseBool(out);
    }
    if (c == 'n') {
      return ParseNull(out);
    }
    return ParseNumber(out);
  }

  bool ParseObject(JsonValue* out) {
    out->type = JsonValue::Type::kObject;
    if (!Consume('{')) {
      return false;
    }
    SkipSpace();
    if (pos_ < text_.size() && text_[pos_] == '}') {
      ++pos_;
      return true;
    }
    while (true) {
      SkipSpace();
      std::string key;
      if (!ParseString(&key)) {
        return false;
      }
      SkipSpace();
      if (!Consume(':')) {
        return false;
      }
      JsonValue value;
      if (!ParseValue(&value)) {
        return false;
      }
      out->object_value.emplace_back(std::move(key), std::move(value));
      SkipSpace();
      if (pos_ < text_.size() && text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      return Consume('}');
    }
  }

  bool ParseArray(JsonValue* out) {
    out->type = JsonValue::Type::kArray;
    if (!Consume('[')) {
      return false;
    }
    SkipSpace();
    if (pos_ < text_.size() && text_[pos_] == ']') {
      ++pos_;
      return true;
    }
    while (true) {
      JsonValue value;
      if (!ParseValue(&value)) {
        return false;
      }
      out->array_value.push_back(std::move(value));
      SkipSpace();
      if (pos_ < text_.size() && text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      return Consume(']');
    }
  }

  bool ParseString(std::string* out) {
    out->clear();
    if (!Consume('"')) {
      return false;
    }
    while (pos_ < text_.size()) {
      const char c = text_[pos_++];
      if (c == '"') {
        return true;
      }
      if (c != '\\') {
        out->push_back(c);
        continue;
      }
      if (pos_ >= text_.size()) {
        return Fail("unterminated escape");
      }
      const char esc = text_[pos_++];
      switch (esc) {
        case '"':
        case '\\':
        case '/':
          out->push_back(esc);
          break;
        case 'b':
          out->push_back('\b');
          break;
        case 'f':
          out->push_back('\f');
          break;
        case 'n':
          out->push_back('\n');
          break;
        case 'r':
          out->push_back('\r');
          break;
        case 't':
          out->push_back('\t');
          break;
        case 'u': {
          // Vectors are ASCII; accept \u only for code points < 0x80.
          if (pos_ + 4 > text_.size()) {
            return Fail("truncated \\u escape");
          }
          const std::string digits = text_.substr(pos_, 4);
          pos_ += 4;
          const long code = std::strtol(digits.c_str(), nullptr, 16);
          if (code <= 0 || code > 0x7f) {
            return Fail("unsupported \\u escape (vectors are ASCII)");
          }
          out->push_back(static_cast<char>(code));
          break;
        }
        default:
          return Fail("unknown escape");
      }
    }
    return Fail("unterminated string");
  }

  bool ParseNumber(JsonValue* out) {
    const std::size_t start = pos_;
    if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) {
      ++pos_;
    }
    bool digits = false;
    while (pos_ < text_.size() &&
           (std::isdigit(static_cast<unsigned char>(text_[pos_])) || text_[pos_] == '.' ||
            text_[pos_] == 'e' || text_[pos_] == 'E' || text_[pos_] == '-' || text_[pos_] == '+')) {
      digits = true;
      ++pos_;
    }
    if (!digits) {
      return Fail("expected value");
    }
    out->type = JsonValue::Type::kNumber;
    out->number_value = std::strtod(text_.substr(start, pos_ - start).c_str(), nullptr);
    return true;
  }

  bool ParseBool(JsonValue* out) {
    if (text_.compare(pos_, 4, "true") == 0) {
      pos_ += 4;
      out->type = JsonValue::Type::kBool;
      out->bool_value = true;
      return true;
    }
    if (text_.compare(pos_, 5, "false") == 0) {
      pos_ += 5;
      out->type = JsonValue::Type::kBool;
      out->bool_value = false;
      return true;
    }
    return Fail("invalid literal");
  }

  bool ParseNull(JsonValue* out) {
    if (text_.compare(pos_, 4, "null") != 0) {
      return Fail("invalid literal");
    }
    pos_ += 4;
    out->type = JsonValue::Type::kNull;
    return true;
  }

  const std::string& text_;
  std::size_t pos_ = 0;
  std::string error_;
};

int HexDigit(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

}  // namespace

std::size_t JsonValue::size() const {
  if (type == Type::kArray) {
    return array_value.size();
  }
  if (type == Type::kObject) {
    return object_value.size();
  }
  if (type == Type::kString) {
    return string_value.size();
  }
  return 0;
}

bool ParseJson(const std::string& text, JsonValue* out, std::string* error) {
  if (out == nullptr) {
    return false;
  }
  *out = JsonValue();
  Parser parser(text);
  return parser.Parse(out, error);
}

bool LoadJsonFile(const std::string& path, JsonValue* out, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error != nullptr) {
      *error = "cannot open " + path;
    }
    return false;
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return ParseJson(buffer.str(), out, error);
}

const JsonValue* Find(const JsonValue& object, const std::string& key) {
  if (object.type != JsonValue::Type::kObject) {
    return nullptr;
  }
  for (const auto& entry : object.object_value) {
    if (entry.first == key) {
      return &entry.second;
    }
  }
  return nullptr;
}

bool GetString(const JsonValue& object, const std::string& key, std::string* out) {
  const JsonValue* value = Find(object, key);
  if (value == nullptr || value->type != JsonValue::Type::kString) {
    return false;
  }
  *out = value->string_value;
  return true;
}

bool GetInt(const JsonValue& object, const std::string& key, long long* out) {
  const JsonValue* value = Find(object, key);
  if (value == nullptr || value->type != JsonValue::Type::kNumber) {
    return false;
  }
  *out = static_cast<long long>(value->number_value);
  return true;
}

bool GetBool(const JsonValue& object, const std::string& key, bool* out) {
  const JsonValue* value = Find(object, key);
  if (value == nullptr || value->type != JsonValue::Type::kBool) {
    return false;
  }
  *out = value->bool_value;
  return true;
}

std::vector<std::uint8_t> HexToBytes(const std::string& hex) {
  std::vector<std::uint8_t> bytes;
  if (hex.size() % 2 != 0) {
    return bytes;
  }
  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = HexDigit(hex[i]);
    const int lo = HexDigit(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return std::vector<std::uint8_t>();
    }
    bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return bytes;
}

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  static const char* kDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    hex.push_back(kDigits[data[i] >> 4]);
    hex.push_back(kDigits[data[i] & 0x0f]);
  }
  return hex;
}

std::string BytesToHex(const std::vector<std::uint8_t>& data) {
  return BytesToHex(data.data(), data.size());
}

}  // namespace test
}  // namespace kcp
