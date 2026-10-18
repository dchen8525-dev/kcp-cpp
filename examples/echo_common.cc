// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors

#include "echo_common.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace echo {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline std::uint32_t Rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// Parses one decimal flag value. Rejects trailing garbage so a typo does not silently become 0.
bool ParseInt(const std::string& text, int* out) {
  if (text.empty()) return false;
  char* end = nullptr;
  const long value = std::strtol(text.c_str(), &end, 10);
  if (end == nullptr || *end != '\0') return false;
  *out = static_cast<int>(value);
  return true;
}

// Go's kcpcrypt.PadKey: copy into a fresh buffer of `size` bytes, zero-padded or truncated.
std::vector<std::uint8_t> PadKey(const std::string& key, std::size_t size) {
  std::vector<std::uint8_t> out(size, 0);
  const std::size_t n = key.size() < size ? key.size() : size;
  std::memcpy(out.data(), key.data(), n);
  return out;
}

}  // namespace

Sha256::Sha256() {
  state_[0] = 0x6a09e667;
  state_[1] = 0xbb67ae85;
  state_[2] = 0x3c6ef372;
  state_[3] = 0xa54ff53a;
  state_[4] = 0x510e527f;
  state_[5] = 0x9b05688c;
  state_[6] = 0x1f83d9ab;
  state_[7] = 0x5be0cd19;
}

void Sha256::Compress(const std::uint8_t block[64]) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t t1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(const void* data, std::size_t len) {
  if (finished_ || len == 0) return;
  const auto* p = static_cast<const std::uint8_t*>(data);
  total_bits_ += static_cast<std::uint64_t>(len) * 8;

  if (buffered_ > 0) {
    const std::size_t take = len < (64 - buffered_) ? len : (64 - buffered_);
    std::memcpy(buffer_ + buffered_, p, take);
    buffered_ += take;
    p += take;
    len -= take;
    if (buffered_ == 64) {
      Compress(buffer_);
      buffered_ = 0;
    }
  }
  while (len >= 64) {
    Compress(p);
    p += 64;
    len -= 64;
  }
  if (len > 0) {
    std::memcpy(buffer_, p, len);
    buffered_ = len;
  }
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::Final() {
  if (!finished_) {
    const std::uint64_t bits = total_bits_;
    const std::uint8_t pad = 0x80;
    Update(&pad, 1);
    const std::uint8_t zero = 0;
    while (buffered_ != 56) Update(&zero, 1);
    std::uint8_t length[8];
    for (int i = 0; i < 8; ++i) {
      length[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    }
    Update(length, sizeof(length));
    finished_ = true;
  }

  std::array<std::uint8_t, kDigestSize> digest{};
  for (int i = 0; i < 8; ++i) {
    digest[i * 4] = static_cast<std::uint8_t>(state_[i] >> 24);
    digest[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
    digest[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
  }
  return digest;
}

std::string ToHex(const std::array<std::uint8_t, Sha256::kDigestSize>& digest) {
  static const char* kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(digest.size() * 2);
  for (std::uint8_t byte : digest) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
  }
  return out;
}

std::string Sha256Hex(const void* data, std::size_t len) {
  Sha256 sha;
  sha.Update(data, len);
  return ToHex(sha.Final());
}

bool ParseOptions(int argc, char** argv, Options* out, std::string* error) {
  for (int i = 1; i < argc; ++i) {
    std::string flag = argv[i];
    std::string value;
    bool has_inline_value = false;
    const std::size_t eq = flag.find('=');
    if (eq != std::string::npos) {
      value = flag.substr(eq + 1);
      flag.resize(eq);
      has_inline_value = true;
    }
    while (!flag.empty() && flag.front() == '-') flag.erase(flag.begin());

    // Boolean flags take no value; everything else consumes the next argument.
    if (flag == "discard" && !has_inline_value) {
      out->discard = true;
      continue;
    }

    if (!has_inline_value) {
      if (i + 1 >= argc) {
        *error = "flag -" + flag + " needs a value";
        return false;
      }
      value = argv[++i];
    }

    bool ok = true;
    if (flag == "addr") {
      out->addr = value;
    } else if (flag == "crypt") {
      out->crypt = value;
    } else if (flag == "key") {
      out->key = value;
    } else if (flag == "data") {
      ok = ParseInt(value, &out->data_shards);
    } else if (flag == "parity") {
      ok = ParseInt(value, &out->parity_shards);
    } else if (flag == "sndwnd") {
      ok = ParseInt(value, &out->sndwnd);
    } else if (flag == "rcvwnd") {
      ok = ParseInt(value, &out->rcvwnd);
    } else if (flag == "mtu") {
      ok = ParseInt(value, &out->mtu);
    } else if (flag == "sockbuf") {
      ok = ParseInt(value, &out->sockbuf);
    } else if (flag == "stats") {
      ok = ParseInt(value, &out->stats_ms);
    } else if (flag == "bytes") {
      ok = ParseInt(value, &out->bytes);
    } else if (flag == "chunk") {
      ok = ParseInt(value, &out->chunk);
    } else if (flag == "iters") {
      ok = ParseInt(value, &out->iters);
    } else if (flag == "timeout") {
      ok = ParseInt(value, &out->timeout_ms);
    } else if (flag == "discard") {
      out->discard = value.empty() || value == "1" || value == "true";
    } else if (flag == "dump-packet") {
      out->dump_packet = value;
    } else {
      *error = "unknown flag -" + flag;
      return false;
    }
    if (!ok) {
      *error = "flag -" + flag + " expects an integer, got \"" + value + "\"";
      return false;
    }
  }

  if ((out->data_shards > 0) != (out->parity_shards > 0)) {
    *error = "data and parity shards must both be zero or both be non-zero";
    return false;
  }
  if (out->bytes <= 0 || out->chunk <= 0 || out->iters <= 0) {
    *error = "bytes, chunk and iters must be positive";
    return false;
  }
  return true;
}

bool MakeCrypt(const std::string& name, const std::string& key, kcp::Crypt* out,
               std::string* error) {
  if (name == "none") {
    out->block = kcp::NewNoneBlockCrypt(nullptr, 0);
    return out->block != nullptr;
  }
  if (name == "simplexor") {
    // SimpleXOR pads or truncates the key itself, like the Go constructor (crypt.go).
    out->block =
        kcp::NewSimpleXorBlockCrypt(reinterpret_cast<const std::uint8_t*>(key.data()), key.size());
    return out->block != nullptr;
  }
  if (name == "aes") {
    const std::vector<std::uint8_t> padded = PadKey(key, 16);
    out->block = kcp::NewAesBlockCrypt(padded.data(), padded.size());
    return out->block != nullptr;
  }
  if (name == "aes-gcm") {
    const std::vector<std::uint8_t> padded = PadKey(key, 16);
    out->aead = kcp::NewAesGcmCrypt(padded.data(), padded.size());
    return out->aead != nullptr;
  }
  if (name == "salsa20") {
    const std::vector<std::uint8_t> padded = PadKey(key, 32);
    out->block = kcp::NewSalsa20BlockCrypt(padded.data(), padded.size());
    return out->block != nullptr;
  }
  if (name == "tea") {
    const std::vector<std::uint8_t> padded = PadKey(key, 16);
    out->block = kcp::NewTeaBlockCrypt(padded.data(), padded.size());
    return out->block != nullptr;
  }
  if (name == "xtea") {
    const std::vector<std::uint8_t> padded = PadKey(key, 16);
    out->block = kcp::NewXteaBlockCrypt(padded.data(), padded.size());
    return out->block != nullptr;
  }
  *error = "unknown cipher \"" + name + "\"";
  return false;
}

bool ApplyTuning(const std::shared_ptr<kcp::UdpSession>& session, const Options& options) {
  session->SetNoDelay(1, 10, 2, 1);
  session->SetWindowSize(options.sndwnd, options.rcvwnd);
  // Best effort: a platform that refuses the size keeps its default instead of failing the run.
  static_cast<void>(session->SetReadBuffer(options.sockbuf));
  static_cast<void>(session->SetWriteBuffer(options.sockbuf));
  return session->SetMtu(options.mtu);
}

FirstPacketDump::FirstPacketDump(std::string path) : path_(std::move(path)) {}

void FirstPacketDump::Record(bool outgoing, const std::uint8_t* data, std::size_t len) {
  std::lock_guard<std::mutex> lock(mu_);
  if (path_.empty() || done_) {
    return;
  }
  done_ = true;

  std::FILE* file = std::fopen(path_.c_str(), "wb");
  if (file == nullptr) {
    return;
  }
  std::fprintf(file, "KCPDUMP 1 dir=%s len=%zu\n", outgoing ? "out" : "in", len);
  // 32 bytes per line: "00000000 " then 64 lowercase hex digits.
  static const char kHex[] = "0123456789abcdef";
  for (std::size_t offset = 0; offset < len; offset += 32) {
    std::fprintf(file, "%08zx ", offset);
    for (std::size_t i = offset; i < offset + 32 && i < len; ++i) {
      std::fputc(kHex[data[i] >> 4], file);
      std::fputc(kHex[data[i] & 0x0f], file);
    }
    std::fputc('\n', file);
  }
  std::fclose(file);
}

}  // namespace echo
