// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors

#ifndef KCP_TESTS_JSON_READER_H_
#define KCP_TESTS_JSON_READER_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace kcp {
namespace test {

// Minimal JSON reader for golden vectors. Supports exactly what tools/golden emits:
// null / bool / number / string / array / object. No number formatting, no duplicate-key
// detection, no streaming. Any schema change must update both the Go generator and this file
// (PORTING-PLAN.md §5.6).
struct JsonValue {
  enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };

  Type type = Type::kNull;
  bool bool_value = false;
  double number_value = 0.0;
  std::string string_value;
  std::vector<JsonValue> array_value;
  std::vector<std::pair<std::string, JsonValue>> object_value;

  bool IsNull() const { return type == Type::kNull; }
  bool IsArray() const { return type == Type::kArray; }
  bool IsObject() const { return type == Type::kObject; }
  bool IsString() const { return type == Type::kString; }
  bool IsNumber() const { return type == Type::kNumber; }
  std::size_t size() const;
};

bool ParseJson(const std::string& text, JsonValue* out, std::string* error);
bool LoadJsonFile(const std::string& path, JsonValue* out, std::string* error);

// Object helpers. Return nullptr / false when the key is absent or has the wrong type.
const JsonValue* Find(const JsonValue& object, const std::string& key);
bool GetString(const JsonValue& object, const std::string& key, std::string* out);
bool GetInt(const JsonValue& object, const std::string& key, long long* out);
bool GetBool(const JsonValue& object, const std::string& key, bool* out);

// Hex is the only binary encoding used by the vectors (lowercase, no separators).
std::vector<std::uint8_t> HexToBytes(const std::string& hex);
std::string BytesToHex(const std::uint8_t* data, std::size_t len);
std::string BytesToHex(const std::vector<std::uint8_t>& data);

}  // namespace test
}  // namespace kcp

#endif  // KCP_TESTS_JSON_READER_H_
