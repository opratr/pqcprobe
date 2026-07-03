# pqcprobe

A small command-line TLS probing utility that uses pyOpenSSL to inspect an HTTPS server's TLS configuration, with a focus on post-quantum readiness.

Features:
- Reports negotiated TLS version, cipher, ALPN and certificate summary
- Reports the negotiated key-exchange group and flags whether it is
  post-quantum (e.g. `X25519MLKEM768`) or classical
- Assesses post-quantum posture: enumerates which key-exchange groups the
  server accepts and flags "harvest-now, decrypt-later" (HNDL) risk when no
  post-quantum key exchange is offered
- Verifies the certificate matches the requested hostname (SAN/CN, wildcard
  and IP aware)
- Probes server support for TLS 1.3 and TLS 1.2
- Samples which TLS 1.2 ciphers the server accepts (and attempts TLS 1.3 ciphersuites where supported by OpenSSL)
- Can fetch raw PEM for the server certificate (--raw-cert)
- Concurrency option for probing (--concurrency)
- Human-friendly summary (--pretty) or JSON output (--json)
- Meaningful exit codes for scripting (see below)

Requirements:
- Python 3.9+
- pyOpenSSL, cryptography (see `requirements.txt`)
- OpenSSL 3.x recommended (3.5+ for post-quantum group support)

Quick start:

1. Create a virtualenv and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

2. Run the probe:

```bash
python3 pqcprobe.py https://example.com --pretty
python3 pqcprobe.py example.com:443 --json
python3 pqcprobe.py example.com:443 --raw-cert

# Post-quantum audit: fail (exit 3) if the server offers no PQC key exchange
python3 pqcprobe.py https://example.com --fail-on-classical-only
# Skip group probing entirely (e.g. when the openssl CLI is unavailable)
python3 pqcprobe.py https://example.com --no-groups
```

Post-quantum key-exchange probing:
- Enumerating group support forces individual groups via the native `openssl`
  CLI, since pyOpenSSL does not expose a way to set the group list. OpenSSL 3.5+
  is required for the ML-KEM hybrid groups (`X25519MLKEM768`, etc.). Groups the
  local openssl doesn't recognize are reported as "not testable" rather than
  "unsupported" (relevant on macOS, whose system openssl is LibreSSL).
- Reading the *negotiated* group uses pyOpenSSL's `Connection.get_group_name()`
  and needs no external tools.

Exit codes:
- `0` success
- `1` handshake failed
- `2` certificate hostname mismatch (when verifying)
- `3` no post-quantum key exchange offered (only with `--fail-on-classical-only`)

Notes:
- Programmatic overriding of TLS 1.3 ciphersuites requires a recent OpenSSL + pyOpenSSL exposing `set_ciphersuites`.
- Cipher probing may produce handshake failures for many ciphers — the tool records successes and errors.

License: MIT (use as you like)

