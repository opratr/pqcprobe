# Decision Log

A running record of notable decisions for pqcprobe — the *why* behind choices
that the code and commit history don't make obvious on their own. Newest entries
at the bottom. Each entry: context, the decision, and its status.

---

## 0001 — Purpose: post-quantum readiness auditing (2026-07-03)

**Context.** The tool is used to audit our own systems in preparation for
post-quantum cryptography risk, specifically "harvest-now, decrypt-later"
(HNDL) exposure.

**Decision.** Treat the TLS **key-exchange group** as the primary signal, not
the symmetric cipher. HNDL risk lives in the key exchange: a session whose keys
are agreed with classical-only ECDHE can be recorded today and decrypted once a
cryptographically relevant quantum computer exists. The tool's reporting and
future features are prioritized accordingly.

**Status.** Accepted.

---

## 0005 — Dependency and platform baseline (2026-07-03)

**Context.** Dependencies were pinned to older releases, and the CI matrix
tested Python 3.8 — which neither pinned dependency supports (both require
Python >= 3.9), so the 3.8 job could never install.

**Decision.** Baseline is Python 3.9+ with pyOpenSSL 26.3.0 and cryptography
49.0.0 (latest stable as of this date). OpenSSL 3.5+ is recommended because it
ships native ML-KEM and enables the hybrid `X25519MLKEM768` group by default,
which the PQC work depends on. CI tests Python 3.9–3.13.

**Status.** Accepted.

---

## 0006 — PQC group probing approach (2026-07-03)

**Context.** For PQC auditing the tool needs to (a) report the group actually
negotiated and (b) enumerate which groups a server will accept. We evaluated
pyOpenSSL 26.3.0's API for this.

**Findings.**
- `Connection.get_group_name()` **is** available — reading the negotiated group
  (e.g. `X25519MLKEM768` vs. a classical `x25519`) is a clean pure-Python call.
- `set_groups` / `SSL_CTX_set1_groups_list` is **not** bound in pyOpenSSL
  26.3.0, so we cannot force a specific group list from Python to enumerate
  server support.

**Decision.** Report the negotiated group via `get_group_name()`. Enumerate
server support by shelling out to the native `openssl s_client -groups <group>`
(OpenSSL 3.5.x supports all ML-KEM hybrids). Flag any server offering only
classical key exchange as an HNDL risk.

**Status.** Implemented on `feature/pqc-group-probing`. Notes from
implementation: openssl only prints the `Negotiated TLS1.3 group:` line for
some groups, so handshake success is detected via a real negotiated cipher and
the forced group is recorded as the one used. Groups the local openssl does not
recognize are reported as `unknown_locally` (not `unsupported`). Added
`--fail-on-classical-only` (exit 3) for audit pipelines and `--no-groups` to
skip probing when the openssl CLI is unavailable.

---

## 0007 — Project name: pqcprobe (2026-07-03)

**Context.** Before publishing a public GitHub repo we checked the working names
for conflicts. `tlsprobe` collides with an archived C tool
(github.com/marcobellaccini/tlsprobe) and sits near `tls_prober` / `tlsprober`;
`TLS-Audit`/`tlsaudit` collides with an active, feature-similar Go tool
(github.com/adedayo/tlsaudit). Both original names are generic and neither
signals the post-quantum focus that differentiates this tool.

**Decision.** Rename the project and CLI to **pqcprobe** ("PQC probe"). It is
unused on PyPI and GitHub and elsewhere on the web, reads clearly, and escapes
the crowded generic TLS-scanner namespace. Renamed the module
(`tlsprobe.py` -> `pqcprobe.py`), test file, and all references.

**Follow-up.** The local working directory is still `TLS-Audit`; name the public
GitHub repo `pqcprobe` at creation for consistency. The PyPI name `pqcprobe` is
available if we later publish.

**Status.** Accepted.
