# tlsprobe

A small command-line TLS probing utility that uses pyOpenSSL to inspect an HTTPS server's TLS configuration.

Features:
- Reports negotiated TLS version, cipher, ALPN and certificate summary
- Probes server support for TLS 1.3 and TLS 1.2
- Samples which TLS 1.2 ciphers the server accepts (and attempts TLS 1.3 ciphersuites where supported by OpenSSL)
- Can fetch raw PEM for the server certificate (--raw-cert)
- Concurrency option for probing (--concurrency)
- Human-friendly summary (--pretty) or JSON output (--json)

Requirements:
- Python 3.8+
- pyOpenSSL, cryptography (see `requirements.txt`)

Quick start:

1. Create a virtualenv and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

2. Run the probe:

```bash
python3 tlsprobe.py https://example.com --pretty
python3 tlsprobe.py example.com:443 --json
python3 tlsprobe.py example.com:443 --raw-cert
```

Notes:
- Programmatic overriding of TLS 1.3 ciphersuites requires a recent OpenSSL + pyOpenSSL exposing `set_ciphersuites`.
- Cipher probing may produce handshake failures for many ciphers — the tool records successes and errors.

License: MIT (use as you like)

