# Contributing to pqcprobe

Thanks for your interest in improving pqcprobe. This is a TLS auditing tool with
a focus on post-quantum readiness; contributions that improve correctness,
coverage of key-exchange groups, and portability are especially welcome.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

For the post-quantum key-exchange group probing you also need the `openssl` CLI
on your PATH, ideally OpenSSL 3.5+ (which ships the ML-KEM hybrid groups).
On macOS the system `openssl` is LibreSSL and will not recognize those groups;
install OpenSSL 3.5+ (e.g. via Homebrew) for full functionality.

## Running the tests

```bash
python3 -m unittest discover -v tests
```

The unit tests are fully offline (target parsing, hostname matching, and
openssl-output classification), so they run without network access.

## Workflow

- Work on a feature branch; do not commit directly to `main`.
- Keep changes focused and include tests for new behavior.
- Run the test suite before opening a pull request.
- If your change involves a notable design decision, add an entry to
  `docs/DECISIONS.md` explaining the context and rationale.

## Reporting bugs and requesting features

Please open a GitHub issue with a clear description, the command you ran, and
the observed vs. expected output. For security-sensitive reports, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE) that covers this project.
