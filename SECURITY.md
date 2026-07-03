# Security Policy

## Scope

pqcprobe is a defensive security tool for auditing the TLS configuration of
servers **you are authorized to test**. Only use it against systems you own or
have explicit permission to assess.

## Reporting a vulnerability

If you discover a security issue in pqcprobe itself (for example, a flaw that
could cause it to misreport a server as secure, or that could harm the machine
running it), please report it privately rather than opening a public issue.

- Email: **andre@vanklaverens.com**
- Please include a description, reproduction steps, and the affected version
  (`pqcprobe --help` or the `__version__` in `pqcprobe.py`).

You can expect an initial acknowledgement within a few business days. Please
give a reasonable period for a fix before any public disclosure.

## Supported versions

This project is pre-1.0; security fixes are applied to the latest released
version on the `main` branch.
