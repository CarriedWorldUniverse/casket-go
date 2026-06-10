# casket-go

[![CI](https://github.com/CarriedWorldUniverse/casket-go/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CarriedWorldUniverse/casket-go/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/CarriedWorldUniverse/casket-go?include_prereleases&sort=semver&display_name=tag)](https://github.com/CarriedWorldUniverse/casket-go/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/CarriedWorldUniverse/casket-go.svg)](https://pkg.go.dev/github.com/CarriedWorldUniverse/casket-go)
[![License](https://img.shields.io/github/license/CarriedWorldUniverse/casket-go)](LICENSE)

Go port of the `casket-ts` channel — Ed25519 + ECDH channel identity, plus
at-rest AEAD envelope encryption and an HKDF-Ed25519 agent-key helper.

Used across the platform for pair-relay channels, at-rest envelope encryption
(e.g. porter blobs), and deriving named agent identities (`DeriveAgentKey`).

Cross-compatible channel wire format with [casket-ts](https://github.com/CarriedWorldUniverse/casket-ts) (Node.js / Cloudflare Workers) and [casket-dotnet](https://github.com/CarriedWorldUniverse/casket-dotnet) (.NET).

## License

Apache-2.0. See [LICENSE](LICENSE).
