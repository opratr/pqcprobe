# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-03

Initial release.

### Added
- Report negotiated TLS version, cipher, ALPN, and certificate summary.
- Report the negotiated key-exchange group and flag it as post-quantum
  (ML-KEM / Kyber) or classical.
- Post-quantum posture assessment: enumerate which key-exchange groups a server
  accepts (via the `openssl` CLI) and flag harvest-now-decrypt-later (HNDL) risk
  when no post-quantum key exchange is offered.
- Certificate hostname verification (SAN/CN, wildcard and IP aware).
- Probe TLS 1.2 / TLS 1.3 support and sample accepted ciphers.
- `--raw-cert`, `--pretty`, `--json`, `--concurrency`, `--no-groups`, and
  `--fail-on-classical-only` options.
- Meaningful exit codes for scripting (0 ok, 1 handshake failure, 2 hostname
  mismatch, 3 no post-quantum key exchange with `--fail-on-classical-only`).
- Packaging: installable via pip with a `pqcprobe` console command.

[Unreleased]: https://github.com/opratr/pqcprobe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/opratr/pqcprobe/releases/tag/v0.1.0
