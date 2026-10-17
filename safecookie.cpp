// SPDX-License-Identifier: GPL-2.0-or-later
// SAFECOOKIE block in original TorPlugin.ControlConnection.connect:
// ae8efb8d40fb38246ac1790ab5cfb11584689c4a, Copyright2013 Azureus Software, Inc.
#include "safecookie.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
namespace biglybtc::plugins::tor {
namespace {
constexpr std::string_view serverLabel = "Tor safe cookie authentication server-to-controller hash";
constexpr std::string_view clientLabel = "Tor safe cookie authentication controller-to-server hash";
std::string hex(std::span<const std::uint8_t> bytes) {
  constexpr std::string_view digits = "0123456789ABCDEF";
  std::string output; output.reserve(bytes.size() * 2);
  for (const auto byte : bytes) { output += digits[byte >> 4]; output += digits[byte & 15]; }
  return output;
}
std::string_view trim(std::string_view text) {
  while (!text.empty() && static_cast<unsigned char>(text.front()) <= 32) { text.remove_prefix(1); }
  while (!text.empty() && static_cast<unsigned char>(text.back()) <= 32) { text.remove_suffix(1); }
  return text;
}
bool singleLine(std::string_view text) { return text.size() <= 1024 && text.find_first_of("\r\n") == text.npos; }
int digit(char byte) {
  if (byte >= '0' && byte <= '9') { return byte - '0'; }
  if (byte >= 'a' && byte <= 'f') { return byte - 'a' + 10; }
  if (byte >= 'A' && byte <= 'F') { return byte - 'A' + 10; }
  return -1;
}
std::expected<std::array<std::uint8_t, 32>, AuthError> decode(std::string_view input) {
  if (input.size() != 64) { return std::unexpected(AuthError::InvalidChallenge); }
  std::array<std::uint8_t, 32> output{};
  for (std::size_t i = 0; i < output.size(); ++i) {
    const int high = digit(input[2 * i]), low = digit(input[2 * i + 1]);
    if (high < 0 || low < 0) { return std::unexpected(AuthError::InvalidChallenge); }
    output[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return output;
}
struct SensitiveMessage {
  std::array<std::uint8_t, 96> bytes{};
  ~SensitiveMessage() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
std::expected<std::array<std::uint8_t, 32>, AuthError> mac(std::string_view label,
    const SensitiveMessage& message) {
  std::array<std::uint8_t, 32> output{};
  std::size_t written = 0;
  if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, label.data(), label.size(),
      message.bytes.data(), message.bytes.size(), output.data(), output.size(), &written)
      || written != output.size()) { return std::unexpected(AuthError::CryptoFailure); }
  return output;
}
}
std::expected<std::string, AuthError> challengeCommand(std::span<const std::uint8_t> clientNonce) {
  if (clientNonce.size() != 32) { return std::unexpected(AuthError::InvalidInput); }
  return "AUTHCHALLENGE SAFECOOKIE " + hex(clientNonce);
}
std::expected<std::string, AuthError> controllerCommand(std::span<const std::uint8_t> cookie,
    std::span<const std::uint8_t> clientNonce, std::string_view challengeReply) {
  if (cookie.size() != 32 || clientNonce.size() != 32) { return std::unexpected(AuthError::InvalidInput); }
  if (!singleLine(challengeReply)) { return std::unexpected(AuthError::InvalidChallenge); }
  auto reply = trim(challengeReply);
  constexpr std::string_view prefix = "250 AUTHCHALLENGE SERVERHASH=";
  constexpr std::string_view separator = " SERVERNONCE=";
  if (!reply.starts_with(prefix)) { return std::unexpected(AuthError::InvalidChallenge); }
  reply.remove_prefix(prefix.size());
  if (reply.size() != 64 + separator.size() + 64 || reply.substr(64, separator.size()) != separator) {
    return std::unexpected(AuthError::InvalidChallenge);
  }
  const auto serverHash = decode(reply.substr(0, 64));
  const auto serverNonce = decode(reply.substr(64 + separator.size()));
  if (!serverHash || !serverNonce) { return std::unexpected(AuthError::InvalidChallenge); }
  SensitiveMessage message;
  std::copy(cookie.begin(), cookie.end(), message.bytes.begin());
  std::copy(clientNonce.begin(), clientNonce.end(), message.bytes.begin() + 32);
  std::copy(serverNonce->begin(), serverNonce->end(), message.bytes.begin() + 64);
  const auto serverProof = mac(serverLabel, message);
  if (!serverProof) { return std::unexpected(serverProof.error()); }
  if (CRYPTO_memcmp(serverProof->data(), serverHash->data(), serverHash->size()) != 0) {
    return std::unexpected(AuthError::IncorrectServerProof);
  }
  auto controllerProof = mac(clientLabel, message);
  if (!controllerProof) { return std::unexpected(controllerProof.error()); }
  auto command = "AUTHENTICATE " + hex(*controllerProof);
  OPENSSL_cleanse(controllerProof->data(), controllerProof->size());
  return command;
}
bool authenticationAccepted(std::string_view reply) {
  return singleLine(reply) && trim(reply).starts_with("250 OK");
}
}
