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

Start it manually from **Actions → Run workflow** (or `gh workflow run compatibility.yml -R d00rsfan/BiglyBTC-plugin-aznettor`). It requires a separately provisioned Linux x64 runner with labels `self-hosted`, `Linux`, `X64`, and `biglybtc-linux`, plus the pinned toolchain and dependencies used by the recipe. Registering the workflow does not provision that runner; a run stays queued until a matching runner is online. It does not run on pull requests.

For future workflow changes, push using this repository's SSH URL (`git@github.com:d00rsfan/BiglyBTC-plugin-aznettor.git`). HTTPS pushes authenticated with an OAuth token require the additional `workflow` scope to add or update workflow files. Viewing public Actions runs does not require that scope.
