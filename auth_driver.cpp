// SPDX-License-Identifier: GPL-2.0-or-later
#include "safecookie.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
namespace tor = biglybtc::plugins::tor;
std::string hex(std::string_view text) {
  std::ostringstream output; output << 'x' << std::hex << std::uppercase << std::setfill('0');
  for (const unsigned char byte : text) { output << std::setw(2) << static_cast<unsigned>(byte); }
  return output.str();
}
std::string bytes(const std::string& text) {
  if (text.empty() || text[0] != 'x' || text.size() % 2 != 1) { throw std::runtime_error("Invalid token"); }
  std::string output;
  for (std::size_t i = 1; i < text.size(); i += 2) { output += static_cast<char>(std::stoul(text.substr(i, 2), nullptr, 16)); }
  return output;
}
std::span<const std::uint8_t> span(const std::string& bytes) {
  return {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};
}
int main(int argc, char** argv) {
  if (argc != 2) { return 2; }
  const auto path = std::filesystem::canonical(argv[1]);
  if (!path.native().starts_with("/tmp/biglybtc-") || std::filesystem::file_size(path) > 4 * 1024 * 1024) { return 2; }
  std::ifstream stream(path);
  if (!stream.good()) { return 3; }
  std::string line;
  while (std::getline(stream, line)) {
    std::istringstream input(line); std::string a, b, c, d; input >> a >> b >> c >> d;
    const auto cookie = bytes(a), nonce = bytes(b), challenge = bytes(c), ack = bytes(d);
    const auto request = tor::challengeCommand(span(nonce));
    if (!request) { std::cout << "REJECT x x\n"; continue; }
    const auto proof = tor::controllerCommand(span(cookie), span(nonce), challenge);
    std::cout << (proof && tor::authenticationAccepted(ack) ? "OK " : "REJECT ") << hex(*request)
        << ' ' << (proof ? hex(*proof) : "x") << '\n';
  }
}
