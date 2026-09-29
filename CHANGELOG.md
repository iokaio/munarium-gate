# Munarium Gate release notes

No release has been made. The entries below record the repository's history until the first tagged
release. A release entry states what the release commits to and lists its accepted limitations; a
capability absent from that list is not implied by the release name.

## Unreleased

- **Build preparation.** Added a non-publishable Rust library under `src/`, dependency-free
  Cargo metadata and lockfile, documented local module interfaces, automatic Rust checks,
  and indexed architecture, implementation and validation guides. No runtime or wire contract
  is implemented; functional capabilities and catalog state remain planned.

- **28 September 2026.** Repository created as a public skeleton: an Apache-2.0 `LICENSE` and a
  one-line `README.md` carrying the GitHub description, "Policy decision and enforcement point for every tool call".
- **Governance and contribution files.** `README.md` with scope, status, planned design and
  acceptance evidence; `NOTICE`; `SECURITY.md`; `CONTRIBUTING.md`; `SUPPORT.md`;
  `CODE_OF_CONDUCT.md`; `TRADEMARK.md`; `AGENTS.md` and its identical copy `CLAUDE.md`; issue and
  pull request templates; `CODEOWNERS` and `FUNDING.yml`; the DCO and repository-hygiene workflows
  with the checks they run (`check_license.py`, `scripts/private_material_scan.py`,
  `scripts/docs_linkcheck.py`, gitleaks). `LICENSE` replaced with the canonical Apache-2.0 text so
  that the licence gate can pin it; the copyright line moved to `NOTICE`.

### Status

Planned. Rust interface scaffolding exists; no runtime service, published package or contract implementation exists. The
first useful public increment is a replayable decision engine and a fake-target execution lifecycle; see the README.
