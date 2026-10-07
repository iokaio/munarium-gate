# Stage 1 decisions

The [decision library](../src/decision.rs) implements canonical request validation,
manifest and current binding checks, parameter validation, verified lineage requirements,
typed obligations, deterministic evaluation and replay. It has no execution method.
`decision-only-allow` remains non-executable in every mode. Required recording failure
returns an error, even if the evaluator permitted the proposal.

The [unchanged candidate bundle](../contracts/stage1/README.md) is proposed, not released.
Registry verifies signed v2 candidate manifests. A privileged `Host` must independently
obtain current identity, policy/catalog bindings and authoritative evidence; these Rust
types are not request DTOs or proof of authentication. The composition uses an operator
fixture for decision-only bindings. Registry submissions never activate themselves.

## Evaluator profile

The implemented native profile is OPA 1.21.1 on Windows amd64, SHA-256
`25406f7c6e147d687fd7fd546f835bafa160a6242c605ee94a23ba6cd7bccdcd`.
Download `opa_windows_amd64.exe` from the official
[release](https://github.com/open-policy-agent/opa/releases/tag/v1.21.1), then verify
that digest. No executable is bundled. The official build reports a `-dirty` commit;
pinning it does not establish a reproducible build or production qualification.

The [worker](../scripts/opa_worker.py) uses strict built-in errors, a pure capability
allowlist, a 100 ms invocation deadline and a Windows Job Object limiting each process
to 64 MiB. It removes ambient environment configuration from OPA. Unsupported hosts,
worker/binary/capability substitution, diagnostics, empty or ambiguous native results,
unknown rules and malformed output refuse. This is a process/resource boundary, not an
OS sandbox against a malicious replacement executable or privileged host.

The policy artifact pins engine name/version/binary, worker and capabilities digests,
Rego code, exact allowed evidence uses and determining-rule obligation mappings.
SHA-256 domains are `munarium:decision-policy:v1`, `munarium:opa-capabilities:v1`
and `munarium:decision-replay:v1`, each followed by one zero byte and exact canonical
JSON. Executable, worker and source content hashes use raw SHA-256. These experimental
artifact encodings need hub acceptance before publication as a shared contract.

The worker returns exactly `allow`, `forbid`, `rules`, `predicates`, `diagnostics`.
Any forbid wins. Rule mappings are either null or a distinct-approval obligation with
an approver scope; obligations acquire the exact request and policy digests. Manifest
obligations cannot be removed by a permit. Declared modifiers require Boolean predicates
and may only raise consequence. A replay exports all resolved policy/evidence inputs,
checks an independently stored bundle digest, re-evaluates, and requires exact equality.
Replay of a recorded refusal retrieves that refusal; it does not rerun unavailable services.

## Reproduce

With Rust 1.98.1, Python 3.12+ and the pinned executable:

```console
cargo fetch --locked
cargo fmt --all --check
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
python scripts/check_opa.py --opa PATH_TO_OPA
```

The native check includes allow/deny, missing/type-invalid input, forbidden network/clock
built-ins, a small versus excessive cross-product workload, and a memory-allocation
negative control. A resource refusal is not a measurement of peak resource use.
Rust tests cover the unchanged canonical vectors, manifest/activation/tenant/parameter
refusals, lineage, obligations, evaluator diagnostics, record failure and persisted replay.
Harness owns the actual multi-repository composition recipe. This repository's regular
build needs no sibling checkout. The [service profile](service-profile.md) adds the
mTLS listener, current Server authority and durable decision recovery. Execution
recovery and production qualification remain outside Stage 1.
