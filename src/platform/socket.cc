// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/platform/socket.h"

#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
// FormatMessageA / LocalFree live in windows.h; WIN32_LEAN_AND_MEAN keeps it from re-including
// winsock.h.
#include <windows.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace kcp {
namespace platform {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidNative = INVALID_SOCKET;

NativeSocket ToNative(SocketHandle fd) { return static_cast<NativeSocket>(fd); }
SocketHandle FromNative(NativeSocket s) { return static_cast<SocketHandle>(s); }
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidNative = -1;

NativeSocket ToNative(SocketHandle fd) { return fd; }
SocketHandle FromNative(NativeSocket s) { return s; }
#endif

sockaddr* AsSockAddr(unsigned char* storage) { return reinterpret_cast<sockaddr*>(storage); }
const sockaddr* AsSockAddr(const unsigned char* storage) {
  return reinterpret_cast<const sockaddr*>(storage);
}

}  // namespace

SocketAddress::SocketAddress() {
  std::memset(storage_, 0, sizeof(storage_));
  len_ = 0;
}

bool SocketAddress::Parse(const std::string& ip, std::uint16_t port, SocketAddress* out) {
  if (out == nullptr) {
    return false;
  }
  std::memset(out->storage_, 0, sizeof(out->storage_));
  out->len_ = 0;

  if (ip.find(':') != std::string::npos) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(out->storage_);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &addr6->sin6_addr) != 1) {
      return false;
    }
    out->len_ = static_cast<int>(sizeof(sockaddr_in6));
    return true;
  }

  auto* addr4 = reinterpret_cast<sockaddr_in*>(out->storage_);
  addr4->sin_family = AF_INET;
  addr4->sin_port = htons(port);
  if (inet_pton(AF_INET, ip.c_str(), &addr4->sin_addr) != 1) {
    return false;
  }
  out->len_ = static_cast<int>(sizeof(sockaddr_in));
  return true;
}

std::string SocketAddress::ToString() const {
  if (len_ == 0) {
    return std::string();
  }
  char host[INET6_ADDRSTRLEN] = {0};
  const sockaddr* sa = AsSockAddr(storage_);
  std::uint16_t port = 0;
  if (sa->sa_family == AF_INET) {
    const auto* addr4 = reinterpret_cast<const sockaddr_in*>(sa);
    inet_ntop(AF_INET, &addr4->sin_addr, host, sizeof(host));
    port = ntohs(addr4->sin_port);
  } else if (sa->sa_family == AF_INET6) {
    const auto* addr6 = reinterpret_cast<const sockaddr_in6*>(sa);
    inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
    port = ntohs(addr6->sin6_port);
    return std::string("[") + host + "]:" + std::to_string(port);
  } else {
    return std::string();
  }
  return std::string(host) + ":" + std::to_string(port);
}

const void* SocketAddress::data() const { return storage_; }

void* SocketAddress::mutable_data() { return storage_; }

int SocketAddress::mutable_size() const {
  // recvfrom() may write up to this many bytes; report the storage capacity so an IPv6 peer fits
  // even when the caller created an IPv4-shaped address.
  return kStorageSize;
}

bool SocketAddress::operator==(const SocketAddress& other) const {
  if (len_ != other.len_) {
    return false;
  }
  if (len_ == 0) {
    return true;
  }
  if (AsSockAddr(storage_)->sa_family != AsSockAddr(other.storage_)->sa_family) {
    return false;
  }
  if (len_ == static_cast<int>(sizeof(sockaddr_in))) {
    const auto* a = reinterpret_cast<const sockaddr_in*>(storage_);
    const auto* b = reinterpret_cast<const sockaddr_in*>(other.storage_);
    return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
  }
  if (len_ == static_cast<int>(sizeof(sockaddr_in6))) {
    const auto* a = reinterpret_cast<const sockaddr_in6*>(storage_);
    const auto* b = reinterpret_cast<const sockaddr_in6*>(other.storage_);
    return a->sin6_port == b->sin6_port &&
           std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0;
  }
  return std::memcmp(storage_, other.storage_, static_cast<std::size_t>(len_)) == 0;
}

// Non-inline copy/move are implicit; storage_ is a plain array so the default ones are correct.
// (Declared implicitly on purpose: no manual resource management.)

bool InitSockets() {
#if defined(_WIN32)
  static const bool ok = [] {
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  return ok;
#else
  return true;
#endif
}

void ShutdownSockets() {
#if defined(_WIN32)
  WSACleanup();
#endif
}

int LastError() {
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

std::string ErrorMessage(int err) {
#if defined(_WIN32)
  char* buffer = nullptr;
  const DWORD len = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, static_cast<DWORD>(err), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
  std::string message;
  if (len != 0 && buffer != nullptr) {
    message.assign(buffer, len);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
      message.pop_back();
    }
  }
  if (buffer != nullptr) {
    LocalFree(buffer);
  }
  if (message.empty()) {
    message = "error " + std::to_string(err);
  }
  return message;
#else
  return std::string(std::strerror(err));
#endif
}

SocketHandle SysSocketUdp() {
  InitSockets();
  return FromNative(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
}

int SysBind(SocketHandle fd, const SocketAddress& addr) {
  NativeSocket sock = ToNative(fd);
  return ::bind(sock, AsSockAddr(reinterpret_cast<const unsigned char*>(addr.data())), addr.size());
}

int SysGetSockName(SocketHandle fd, SocketAddress* addr) {
  if (addr == nullptr) {
    return -1;
  }
  NativeSocket sock = ToNative(fd);
  unsigned char scratch[128];
  std::memset(scratch, 0, sizeof(scratch));
#if defined(_WIN32)
  int scratch_len = static_cast<int>(sizeof(scratch));
  const int rc = ::getsockname(sock, AsSockAddr(scratch), &scratch_len);
#else
  socklen_t scratch_len = sizeof(scratch);
  const int rc = ::getsockname(sock, AsSockAddr(scratch), &scratch_len);
#endif
  if (rc != 0) {
    return rc;
  }
  std::memcpy(addr->mutable_data(), scratch, static_cast<std::size_t>(scratch_len));
  addr->set_size(static_cast<int>(scratch_len));
  return 0;
}

int SysSendTo(SocketHandle fd, const void* buf, std::size_t len, const SocketAddress& to) {
  NativeSocket sock = ToNative(fd);
#if defined(_WIN32)
  const int sent =
      ::sendto(sock, static_cast<const char*>(buf), static_cast<int>(len), 0,
               AsSockAddr(reinterpret_cast<const unsigned char*>(to.data())), to.size());
#else
  const ssize_t sent =
      ::sendto(sock, buf, len, 0, AsSockAddr(reinterpret_cast<const unsigned char*>(to.data())),
               static_cast<socklen_t>(to.size()));
#endif
  return static_cast<int>(sent);
}

int SysRecvFrom(SocketHandle fd, void* buf, std::size_t len, SocketAddress* from) {
  NativeSocket sock = ToNative(fd);
  // sockaddr_storage sized scratch buffer; never trust the caller's address family.
  unsigned char scratch[128];
  std::memset(scratch, 0, sizeof(scratch));
#if defined(_WIN32)
  int scratch_len = static_cast<int>(sizeof(scratch));
  const int got = ::recvfrom(sock, static_cast<char*>(buf), static_cast<int>(len), 0,
                             AsSockAddr(scratch), &scratch_len);
#else
  socklen_t scratch_len = sizeof(scratch);
  const ssize_t got = ::recvfrom(sock, buf, len, 0, AsSockAddr(scratch), &scratch_len);
#endif
  if (got >= 0 && from != nullptr) {
    if (scratch_len <= from->mutable_size()) {
      std::memcpy(from->mutable_data(), scratch, static_cast<std::size_t>(scratch_len));
      from->set_size(scratch_len);
    }
  }
  return static_cast<int>(got);
}

int SysClose(SocketHandle fd) {
#if defined(_WIN32)
  return ::closesocket(ToNative(fd));
#else
  return ::close(ToNative(fd));
#endif
}

int SysShutdown(SocketHandle fd) {
#if defined(_WIN32)
  return ::shutdown(ToNative(fd), SD_BOTH);
#else
  return ::shutdown(ToNative(fd), SHUT_RDWR);
#endif
}

int SysSetNonBlocking(SocketHandle fd, bool non_blocking) {
#if defined(_WIN32)
  u_long mode = non_blocking ? 1UL : 0UL;
  return ::ioctlsocket(ToNative(fd), FIONBIO, &mode);
#else
  const int flags = ::fcntl(ToNative(fd), F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  const int updated = non_blocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  return ::fcntl(ToNative(fd), F_SETFL, updated);
#endif
}

int SysSetReuseAddr(SocketHandle fd) {
  const int on = 1;
#if defined(_WIN32)
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&on),
                      sizeof(on));
#else
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#endif
}

int SysSetRecvBuffer(SocketHandle fd, int bytes) {
#if defined(_WIN32)
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bytes),
                      sizeof(bytes));
#else
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
#endif
}

int SysSetSendBuffer(SocketHandle fd, int bytes) {
#if defined(_WIN32)
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bytes),
                      sizeof(bytes));
#else
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
#endif
}

int SysSetRecvTimeout(SocketHandle fd, int timeout_ms) {
#if defined(_WIN32)
  const DWORD timeout = static_cast<DWORD>(timeout_ms);
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  return ::setsockopt(ToNative(fd), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

}  // namespace platform
}  // namespace kcp
