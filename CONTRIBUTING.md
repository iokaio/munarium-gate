# Contributing to Munarium Gate

Contributions are welcome from anyone. What follows is the whole process; there is no contributor
license agreement to sign.

## Rights and license

- **Every commit carries a Developer Certificate of Origin sign-off**: `git commit -s`, which adds
  `Signed-off-by: Your Name <you@example.com>`. By signing off you certify the
  [DCO](https://developercertificate.org/), that the work is yours to submit under this
  repository's license, or that you have the right to submit it. A pull request with an unsigned
  commit fails its check.
- **Accepted code is Apache-2.0**, the license of the whole repository ([LICENSE](LICENSE)), by
  section 5 of the license itself: a contribution intentionally submitted for inclusion is licensed
  under the same terms, copyright and patent alike. That is why no CLA exists; a CLA would add the
  right to relicense your contribution later, and that right is not wanted.
- A contribution changes nothing about Ioka's trademarks ([TRADEMARK.md](TRADEMARK.md)) or the
  support boundary ([SUPPORT.md](SUPPORT.md)).

## Disclosure

The pull request template asks four questions; answer each, and "none" is an answer:

1. **third-party code**: any file or fragment you did not write, with its license;
2. **generated code**: what generated it, from what;
3. **AI-tool provenance**: which tools helped, and that you reviewed every line;
4. **employer or contractual restrictions** on what you may contribute.

You must have the right to submit every file in the pull request. Every contribution has a human
submitter who accepts responsibility for it. A model cannot hold maintainer accountability or sign a
contribution on behalf of an unknown person, and a large generated patch without reproducible
evidence is not useful capacity because it arrived through a pull request.

## Process

1. Fork the repository (maintainers: a topic branch) and make the change.
2. Run the gates below. Every new source file carries `SPDX-License-Identifier: Apache-2.0` on its
   first line, the second after a shebang or an XML declaration, and `check_license.py` names any
   file that does not.
3. Open a pull request against `main`. Public CI may fetch pinned public dependencies,
   then run offline suites and isolated service tests with synthetic data. Disposable
   test-only identities, keys and bootstrap bindings have no production trust. Pull
   requests, including forks, receive no production credentials, deployed-environment
   access or release authority. Checks needing those resources use a separately
   authorized trusted environment after merge.
4. A code owner reviews ([.github/CODEOWNERS](.github/CODEOWNERS)); Ioka squash-merges. External
   pull requests never gain deployment or release authority.

A change that touches a cross-component contract or semantic (a wire envelope, the request hash,
the principal chain, the outcome vocabulary, a consequence-class rule) starts as a decision record
in the hub, [iokaio/munarium-platform](https://github.com/iokaio/munarium-platform), and lands here
only after that record exists. The hub's contracts directory is normative; this repository may
narrow what it accepts, it may not redefine what a contract means. Breaking interface changes use
expand, migrate, remove: a producer adds a compatible capability, consumers adopt it, the platform
composition records the transition, and only then is the obsolete contract removed under the
declared version policy.

## Gates

| Gate | Command |
|---|---|
| Licence and notices | `py check_license.py` |
| Private material | `py scripts/private_material_scan.py` |
| Documentation links and indexes | `py scripts/docs_linkcheck.py` |
| Secret scan | `gitleaks dir . --config .gitleaks.toml` |
| Whitespace | `git diff --check` |
| Rust formatting | `cargo fmt --all --check` |
| Rust build | `cargo build --offline --locked` |
| Rust lint | `cargo clippy --offline --locked --all-targets -- -D warnings` |
| Rust tests | `cargo test --offline --locked` |
| API documentation | `cargo doc --offline --locked --no-deps` |

Use `python` or `python3` where `py` is unavailable. Rust checks use 1.98.1 with rustfmt
and Clippy; the new [Rust workflow](.github/workflows/rust.yml) installs that version explicitly.
Commit the lockfile and review/pin dependencies. Fetch locked public dependencies before
running the offline checks. [Validation](docs/validation.md) records implemented checks
and remaining acceptance gaps; passing component tests does not qualify the platform.
The workflows under `.github/workflows/` are the source of truth for automatic coverage.
Add component conformance coverage with each behavior; keep existing automatic suites intact.

Rules the gates and reviewers enforce that are easy to trip:

- **The README's status is a claim with evidence behind it.** The capability table and the status
  label change only in a pull request that adds the evidence; a badge, a branch name or a passing
  documentation job changes nothing. A skeleton says which operations are unavailable.
- **No placeholder service listens on a production interface** to make the repository look
  runnable. A disposable local target is fine; a stub that accepts real traffic is not.
- **Three subsystems, three privilege domains.** Deterministic evaluation, durable execution state and the isolated connector host may share this repository; they may not share unrestricted privileges for convenience.
- **The evaluator makes no unrecorded network calls.** Enrichment is a separate step whose results enter the pinned input bundle with source version and freshness; the decision is reproducible from that bundle, the policy digest and the evaluator version.
- **One policy evaluator in the first release**, chosen by a recorded implementation spike, not two evaluators supported at once.
- **The native Action API is canonical.** MCP is an adapter to it, never a privileged second execution path; REST first, gRPC only after shared semantics have contract tests.
- **No generic shell, unrestricted HTTP, arbitrary SQL, or unbounded file-writing tool is a low-risk capability**, whatever its manifest says.
- **Test fixtures keep their oracle and approval history.** A failing policy test is not made to pass by rewriting its expected result.
- **Tests keep their oracle.** A failing test is fixed at its cause or its scope is narrowed and the
  narrowing recorded; the expected result is not rewritten to pass, and coverage is never relabelled.
- **Every release states its actual trust boundary**, deployment assumptions, unsupported paths and
  residual risks. Missing authority, unavailable evidence, incomplete credential isolation or an
  unqualified connector narrows the release; it is never a reason to waive a control.

## Conduct and venues

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere in this project. Questions go to GitHub
Discussions, defects to Issues, and suspected vulnerabilities to the private channel
[SECURITY.md](SECURITY.md) names, never to a public issue or a proof-of-concept pull request.

## Protected files

Only Ioka changes `LICENSE`, `NOTICE`, `TRADEMARK.md`, this file, `CODE_OF_CONDUCT.md`,
`SECURITY.md`, `SUPPORT.md`, `AGENTS.md` and `CLAUDE.md`, anything under `.github/`, any contract or
vendored contract directory, and any signing or release configuration. A pull request that touches
them is declined unless a maintainer opened it.

The [Stage 1 development authorization](AGENTS.md#stage-1-development-authorization)
is the maintainer's explicit direction to prepare the scoped guidance, build/test
workflow and contract candidate changes. Contributors carrying out that direction
may edit those files; protected-file ownership, review and merge requirements still
apply. It grants no release authority or permission to weaken approval controls.
