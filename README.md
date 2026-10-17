# BiglyBTC-plugin-aznettor

Offline SAFECOOKIE proof library at original aznettor baseline
`ae8efb8d40fb38246ac1790ab5cfb11584689c4a`. This static library is not an
operational plugin module or proxy. It launches no Tor process, opens no sockets,
reads no cookie or profile, modifies no torrc and takes ownership of no process.

The host supplies a32-byte cookie, fresh cryptographic32-byte client nonce and
one decoded control reply. Native OpenSSL3.5.5 HMAC-SHA256 verifies the server
proof with CRYPTO_memcmp before returning the controller proof. Scratch cookie
material is cleansed. Returned proof commands are sensitive; the caller owns
their lifetime and must not log them. No unauthenticated/password fallback exists.

The parser bounds replies to1024 bytes, requires exactly32-byte hashes/nonces and
the original standard ordered SERVERHASH/SERVERNONCE fields, and rejects multiple
lines. Original valid handshakes and failures are characterized by the exact Java
block with supplied cookie/transcripts. This does not claim parity for permissive
malformed replies accepted by the original substring/hex parsing.

Host cryptographic nonce generation, original cookie/onion-identity file access,
framing/events/timeouts, process lifecycle/ownership/idle-stop, proxy privacy and
Qt settings remain required. Production Tor version and dependency packaging are
unselected. GPL-2.0-or-later; original Copyright2013 Azureus Software, Inc.
