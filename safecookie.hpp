// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
namespace biglybtc::plugins::tor {
enum class AuthError { InvalidInput, InvalidChallenge, IncorrectServerProof, CryptoFailure };
// Pure offline functions, no cookie loading, randomness, socket, logging or
// process ownership. The future host must supply a fresh cryptographic nonce.
std::expected<std::string, AuthError> challengeCommand(std::span<const std::uint8_t> clientNonce);
// Exposes a controller proof only after constant-time verification of the peer.
std::expected<std::string, AuthError> controllerCommand(std::span<const std::uint8_t> cookie,
    std::span<const std::uint8_t> clientNonce, std::string_view challengeReply);
bool authenticationAccepted(std::string_view reply);
}
