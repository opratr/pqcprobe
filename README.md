# pqcprobe

[![PyPI](https://img.shields.io/pypi/v/pqcprobe.svg)](https://pypi.org/project/pqcprobe/)
[![Python versions](https://img.shields.io/pypi/pyversions/pqcprobe.svg)](https://pypi.org/project/pqcprobe/)
[![Tests](https://github.com/opratr/pqcprobe/actions/workflows/python-tests.yml/badge.svg)](https://github.com/opratr/pqcprobe/actions/workflows/python-tests.yml)
[![Lint & Security](https://github.com/opratr/pqcprobe/actions/workflows/lint.yml/badge.svg)](https://github.com/opratr/pqcprobe/actions/workflows/lint.yml)
[![CodeQL](https://github.com/opratr/pqcprobe/actions/workflows/codeql.yml/badge.svg)](https://github.com/opratr/pqcprobe/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small command-line TLS probing utility that uses pyOpenSSL to inspect an HTTPS server's TLS configuration, with a focus on post-quantum readiness.

Features:
- Reports negotiated TLS version, cipher, ALPN and certificate summary
- Reports the negotiated key-exchange group and flags whether it is
  post-quantum (e.g. `X25519MLKEM768`) or classical
- Assesses post-quantum posture from verified TLS 1.3 group probes and the
  negotiated session; reports an indeterminate result when testing is incomplete
- Verifies the certificate matches the requested hostname (SAN/CN, wildcard
  and IP aware)
- Probes server support for TLS 1.3 and TLS 1.2
- Samples which TLS 1.2 ciphers the server accepts (and attempts TLS 1.3 ciphersuites where supported by OpenSSL)
- Can fetch raw PEM for the server certificate (--raw-cert)
- Concurrency option for probing (--concurrency)
- Human-friendly summary (--pretty) or JSON output (--json)
- Meaningful exit codes for scripting (see below)

Requirements:
- Python 3.9.2+
- pyOpenSSL, cryptography (installed automatically)
- OpenSSL 3.x recommended (3.5+ for post-quantum group support). On macOS the
  system `openssl` is LibreSSL and cannot test the ML-KEM hybrid groups; install
  OpenSSL 3.5+ (e.g. via Homebrew) for full functionality.

## Install

```bash
pip install pqcprobe
```

This installs a `pqcprobe` command. To run from a source checkout instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

## Usage

```bash
pqcprobe https://example.com --pretty
pqcprobe example.com:443 --json
pqcprobe example.com:443 --raw-cert
pqcprobe example.com:443 --ca-file /path/to/ca-bundle.pem

# Post-quantum audit: fail (exit 3) if the server offers no PQC key exchange
pqcprobe https://example.com --fail-on-classical-only
# Skip group probing entirely (e.g. when the openssl CLI is unavailable)
pqcprobe https://example.com --no-groups
```

(From a source checkout without installing, use `python3 pqcprobe.py ...`.)

Post-quantum key-exchange probing:
- Enumerating group support forces individual groups via the native `openssl`
  CLI, since pyOpenSSL does not expose a way to set the group list. OpenSSL 3.5+
  is required for the ML-KEM hybrid groups (`X25519MLKEM768`, etc.). Groups the
  local openssl doesn't recognize are reported as "not testable" rather than
  "unsupported" (relevant on macOS, whose system openssl is LibreSSL). Each
  probe requires TLS 1.3 and, by default, verifies the certificate and target
  name. Use `--ca-file` for private PKI so Python and the native CLI use the
  same CA bundle.
- Reading the *negotiated* group uses pyOpenSSL's `Connection.get_group_name()`
  and needs no external tools.
- `pqc_ready` and `hndl_risk` are `null` when the assessment is indeterminate.
  Offered hybrid support does not prove that every client negotiates it or that
  historical sessions were protected. Results from `--no-verify` are labeled
  unauthenticated; the policy gate requires verification.
- A certificate without a SAN can still use its actual subject CN for legacy
  compatibility. Certificates with a SAN do not use CN fallback; wildcards must
  occupy the complete leftmost DNS label.

Exit codes:
- `0` success
- `1` handshake failed
- `2` certificate hostname mismatch (when verifying)
- `3` no post-quantum key exchange offered (only with `--fail-on-classical-only`)
- `4` post-quantum assessment indeterminate (only with `--fail-on-classical-only`)

`--fail-on-classical-only` cannot be combined with `--no-groups`, `--no-verify`,
or `--raw-cert`. `--raw-cert` writes only PEM to stdout on success; errors go to
stderr with a nonzero exit code.

Notes:
- Programmatic overriding of TLS 1.3 ciphersuites requires a recent OpenSSL + pyOpenSSL exposing `set_ciphersuites`.
- Cipher probing may produce handshake failures for many ciphers — the tool records successes and errors.
- Only use pqcprobe against systems you own or are authorized to test.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security
issues should be reported privately per [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Andre Van Klaveren
