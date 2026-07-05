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

---

## 0008 — Open-source and packaging setup (2026-07-03)

**Context.** Preparing the project to accept contributions and be published to
PyPI. It previously had no license file, contributor docs, or packaging.

**Decisions.**
- **License:** MIT, © 2026 Andre Van Klaveren (added a real `LICENSE` file to
  back the README's existing claim).
- **Governance:** added `CONTRIBUTING.md`, `SECURITY.md` (private disclosure to
  andre@vanklaverens.com — important for a security tool), `CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), and `CHANGELOG.md` (Keep a Changelog).
- **Packaging:** `pyproject.toml` with the hatchling backend; version is a
  single source of truth read from `__version__` in `pqcprobe.py`; kept the flat
  single-module layout (packaged via `only-include`) rather than moving to
  `src/`, to minimize churn. Exposes a `pqcprobe` console entry point
  (`pqcprobe:main`, which already returned an exit code).
- **Publishing:** GitHub Actions workflow using PyPI Trusted Publishing (OIDC),
  triggered on a published GitHub Release — no API tokens stored. The actual
  upload is a human-triggered release, never automated blindly.

**Follow-ups before first publish.**
- GitHub namespace is `opratr`; project URLs in `pyproject.toml` and
  `CHANGELOG.md` are set accordingly.
- Register a PyPI "pending" trusted publisher for project `pqcprobe`
  (workflow `publish.yml`, environment `pypi`).

**Status.** Accepted; build validated locally (`python -m build` + `twine
check` pass, wheel installs and the `pqcprobe` command runs). Not yet uploaded.

---

## 0009 — Linting and security scanning (2026-07-03)

**Context.** The project had no linting or static/security analysis — the only
automated gate was the unit tests. For an OSS security tool that shells out to
`openssl` and parses untrusted network data, that is a gap.

**Decisions.**
- **Ruff** for linting (rules E/F/W/I/UP), configured in `pyproject.toml` and
  enforced in CI via `ruff check`. `E501` (line length) is left to `ruff format`,
  which is *not* gated — the code is not yet reformatted repo-wide, and a full
  reformat was deliberately avoided to keep diffs reviewable. Import-ordering
  autofixes were applied.
- **Bandit** for Python SAST, gated in CI at **medium+** severity. The current
  code produces only low-severity findings: `B404` (subprocess import) and ~25
  `B110` (try/except/pass). These are accepted as known/architectural — the
  subprocess call is core functionality (annotated with a safety rationale and
  `# noqa: S603`), and the broad excepts are pre-existing tech debt already
  noted in the original review (candidate for a later cleanup). Gating at
  medium+ keeps CI honest without failing on these.
- **pip-audit** scans runtime dependencies (`requirements.txt`) for CVEs in CI.
- **CodeQL** (`github/codeql-action@v4`, `security-and-quality` queries) runs on
  push/PR and weekly.
- **Dependabot** for the `pip` and `github-actions` ecosystems (weekly), which
  also keeps our "use current versions" preference on autopilot.
- **pre-commit** config for local Ruff + hygiene hooks (opt-in, not CI-gating).
- README shows status badges for Tests, Lint & Security, and CodeQL.

**Follow-ups.**
- README badge URLs use the `opratr` namespace; they render once the repo is
  pushed to GitHub.
- Optional future work: reduce the `B110` broad-except count and then consider
  applying `ruff format` repo-wide and gating it.

**Status.** Accepted; all checks pass locally (ruff clean, bandit medium+ clean,
pip-audit clean, 21 tests pass).

---

## 0010 — Hash-pinned runtime dependencies (2026-07-04)

**Context.** For supply-chain integrity we want installs to verify the exact
artifact, not just the version — protecting against a compromised or substituted
package on the index.

**Decisions.**
- Hashes live in a **lockfile**, not in package metadata. `pyproject.toml`
  keeps *abstract* version constraints (what `pip install pqcprobe` resolves for
  end users); `requirements.txt` is a fully pinned, hash-locked lockfile of the
  entire transitive tree (cryptography, cffi, pycparser, pyOpenSSL,
  typing-extensions).
- The lockfile is generated from `requirements.in` with
  `uv pip compile --universal --generate-hashes` — `--universal` embeds
  environment markers so one file is correct across Python 3.9–3.13 (e.g.
  `pycparser` 2.23 for <3.10 vs 3.0 for ≥3.10; `typing-extensions` only <3.13).
- CI's test job installs with `pip install --require-hashes -r requirements.txt`,
  which fails the build if any artifact's hash does not match (verified locally:
  a tampered hash produces "THESE PACKAGES DO NOT MATCH THE HASHES"). Tests run
  without an editable install because `pqcprobe.py` is importable from the repo
  root; the packaged-install path is validated separately in `publish.yml`.
- **`requires-python` tightened to `>=3.9.2`**: surfaced during resolution,
  cryptography 49 excludes Python 3.9.0/3.9.1, so the previous `>=3.9` was
  inaccurate.

**Notes / limits.**
- Dev tools and the build backend were initially unpinned; now addressed in
  [[0011]].
- Dependabot understands hashed requirements and will regenerate hashes on
  updates, so this stays compatible with the "keep versions current" policy.

**Status.** Accepted; hash-verified install confirmed in a clean venv, tests
pass.

---

## 0011 — Hash-pin dev tools and the build backend (2026-07-04)

**Context.** Extends [[0010]] to close the residual unpinned surface: the CI dev
tools (ruff, bandit, pip-audit, build, twine, pre-commit) and the build backend
(hatchling), which `python -m build` otherwise fetches unpinned in an isolated
environment.

**Decisions.**
- Added `requirements-dev.in` -> `requirements-dev.txt`, a universal
  hash-locked lockfile for the dev/CI toolchain (same `uv pip compile` flow as
  the runtime lockfile).
- `lint.yml` installs the tools with `--require-hashes -r requirements-dev.txt`
  instead of an unpinned `pip install`.
- `publish.yml` installs the same pinned set and runs `python -m build
  --no-isolation`, so the build uses the hash-pinned hatchling rather than
  fetching a build backend on the fly.
- `hatchling` is included in the dev lockfile specifically to make the
  no-isolation build verifiable.

**Notes.**
- Universal resolution pins per-Python variants where a tool dropped an older
  interpreter (e.g. `bandit` 1.8.6 on 3.9 vs 1.9.4 on ≥3.10); CI (3.13) gets the
  current releases.
- pre-commit hook repos remain pinned by git `rev` (their native mechanism),
  which is separate from the pip hash lockfiles.

**Status.** Accepted; verified in a clean venv — pinned tools run (ruff, bandit,
pip-audit clean) and `build --no-isolation` + `twine check` pass.
