// SPDX-License-Identifier: GPL-2.0-or-later
#include "safecookie.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
using namespace biglybtc::plugins::tor;
void require(bool value) { if (!value) { std::abort(); } }
int main() {
  std::array<std::uint8_t, 32> cookie{}, client{};
  for (std::size_t i = 0; i < client.size(); ++i) { client[i] = static_cast<std::uint8_t>(i); }
  // First frozen Java observation; fixture generation independently uses Python
  // HMAC for server input, then original JCE validates it and emits this proof.
  const std::string valid = "250 AUTHCHALLENGE SERVERHASH=9AC6D0EF401195DCFCBDCBC6E2876DA2DDB4319D4D92242C4E402C450BA848C8 SERVERNONCE=1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100";
  const std::string expected = "AUTHENTICATE F40A1FFB4D7754B5206A40D9DB648ED970DC28CBF45C2AA35C2A9899AAF5B882";
  require(controllerCommand(cookie, client, valid) == expected);
  require(!challengeCommand(std::span(client).first(31)));
  require(!controllerCommand(std::span(cookie).first(31), client, valid));
  require(!controllerCommand(cookie, std::span(client).first(31), valid));
  for (std::size_t i = 0; i < 64; ++i) {
    auto tampered = valid;
    const auto offset = std::string_view("250 AUTHCHALLENGE SERVERHASH=").size() + i;
    tampered[offset] = tampered[offset] == '0' ? '1' : '0';
    require(!controllerCommand(cookie, client, tampered));
  }
  for (const auto& malformed : {std::string{}, valid + "\r\nAUTHENTICATE 0", valid + " EXTRA=1",
      std::string(1025, 'x'), "250 AUTHCHALLENGE SERVERHASH=" + std::string(64, 'Z') + " SERVERNONCE=" + std::string(64, '0')}) {
    require(!controllerCommand(cookie, client, malformed));
  }
  cookie[31] = 1;
  require(controllerCommand(cookie, client, valid).error() == AuthError::IncorrectServerProof);
  require(authenticationAccepted(" \t250 OK\t "));
  require(!authenticationAccepted("515 Authentication failed"));
  require(!authenticationAccepted("250 OK\r\n515 failed"));
  require(!authenticationAccepted(std::string(1025, ' ')));
  std::cout << "PASS Tor authentication proof verification, input bounds and rejected command injection\n";
}
