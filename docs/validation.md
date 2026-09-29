# Munarium Gate validation

## Build the scaffold locally

Use Rust **1.98.1** with Cargo, rustfmt and Clippy, plus the platform's native linker.
The manifest requires Rust 1.98; older toolchains are not qualified by this scaffold.
CI installs 1.98.1 explicitly. No provider account, database, model key, container, sibling
checkout or downloaded crate is needed for these commands from the repository root:

```console
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

`Cargo.lock` is checked in. Do not regenerate it to bypass a locked-build failure.
The initial lock contains only this package. When external dependencies arrive, pin and
review them and revise the offline setup instructions to identify the required cache.

Build and lint validate the interface declarations. **There are no runtime implementations,
unit tests or conformance tests yet.** A successful `cargo test` with zero tests is only
a scaffold check; the acceptance cases below are specifications, not executed evidence.
`cargo doc` produces local API documentation under `target/doc/`.

Run the existing repository checks too:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` if the `py` launcher is unavailable. The secret command scans
the working tree; the existing hygiene workflow also scans Git history. No local result
is evidence that hosted CI passed.

## Automatic coverage

The new [Rust workflow](../.github/workflows/rust.yml) runs formatting, build, lint, tests
and warning-free API documentation on pushes to main and pull requests. It uses read-only
repository permissions and has no publishing, deployment or provider steps.
The existing [hygiene workflow](../.github/workflows/repo-hygiene.yml) and
[DCO workflow](../.github/workflows/dco.yml) retain their independent checks.

## Required behavioral acceptance cases

These are **not implemented**. Invariant IDs refer to the catalog in
[platform plan revision 4, Appendix C](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) and the
[hub catalog](https://github.com/iokaio/munarium-platform/blob/main/README.md#the-invariant-catalog). No contract bundle has been released.

| Invariant | Scenario | Required observation |
|---|---|---|
| INV-03 / INV-04 | Use forged principal context or unknown/incompatible manifest. | Typed refusal with no target call. |
| INV-06 / INV-09 | Remove lineage or change recipient, artifact, policy epoch, or target version after approval. | Refusal or fresh approval is required. |
| INV-08 / INV-10 | Request a grant without a matching durable claim; race two workers. | No grant for the missing claim; at most one dispatch ownership. |
| INV-11 / INV-19 | Lose the response after target effect, restart, then restore an older snapshot. | Unresolved remains visible; no blind repetition or revived grant. |
| INV-14 | Fail the required proposal, claim, or dispatch journal write. | No new consequential dispatch. |
| INV-20 | Allow locally while a mandatory parent policy denies. | Deny when federation is introduced. |

INV-21 (protected development authority) and INV-22 (claims bounded by evidence)
apply to every packet in addition to the component-specific cases.

## Evidence to retain when the tests exist

Record source and contract digests, toolchain, fixture identifiers, command/exit status,
environment, declared trust boundary, expected and actual outcome, and remaining gaps.
Concurrency, crash/restart, identity, network and storage claims require their real test
environment; an in-memory fake cannot certify them. A live integration needs its own
authorization and qualification record.

Keep operational credentials and raw private payloads out of test artifacts. Distinguish
a local pass, unavailable coverage, a failing case, and an independently reviewed result.
No capability-status or invariant-evidence field advances from the scaffold checks.
