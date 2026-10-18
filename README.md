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

## Continuous integration

The workflow is [`.github/workflows/compatibility.yml`](.github/workflows/compatibility.yml). [View runs](https://github.com/d00rsfan/BiglyBTC-plugin-aznettor/actions).

The workflow runs on GitHub-hosted `ubuntu-26.04` amd64 runners on pushes, pull requests, and manual dispatch. It installs the exact GCC16/libstdc++16 snapshot and pinned Ubuntu dependency packages declared in the workflow; no separately provisioned runner is needed. GCC Release and GCC ASan/UBSan/LSan Debug replay the unchanged offline fixtures and boundary tests. Clang24 remains separately qualified by the local evidence; this hosted workflow does not claim a Clang run. Build/test logs and installed package versions are retained as workflow artifacts. This CI does not publish a release or qualify other distributions.

For future workflow changes, push using this repository's SSH URL (`git@github.com:d00rsfan/BiglyBTC-plugin-aznettor.git`). HTTPS pushes authenticated with an OAuth token require the additional `workflow` scope to add or update workflow files. Viewing public Actions runs does not require that scope.
