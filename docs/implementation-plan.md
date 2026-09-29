# Munarium Gate build plan

**Proposed work; no functional milestone is complete.** The design baseline is the
[public platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), section 8, and its
stage sequence in section 25. Gate's initial delivery belongs to **Stage 1 then 2**.
Calendar windows are planning targets; acceptance evidence controls advancement.

## Preparation present in this checkout

- A non-publishable, dependency-free Cargo library with documented interface modules.
- An [architecture map](architecture.md) naming ownership, trust assumptions and failures.
- An [acceptance specification](validation.md) and automatic Rust build checks.
- Existing contribution, security, support and repository-hygiene processes.

These artifacts prepare implementation; they do not complete Stage 0 foundation qualification
or advance this repository beyond the hub's **repository created** catalog state.

## First work packet: GATE-01: deterministic decision-only evaluation and replay

**Prerequisites:** accepted hub decisions and the specific contracts named in
[Architecture](architecture.md); record the exact revisions used. All fixtures must be synthetic
or authorized public inputs. The hub [contract backlog](https://github.com/iokaio/munarium-platform/blob/main/docs/architecture/contract-backlog.md)
tracks unresolved cross-component definitions.

**Work:** After the canonical request and evaluator decisions are accepted, evaluate a synthetic release proposal from a pinned manifest, policy, principal record, and evidence snapshot. Keep connector dispatch disconnected. Record engine and policy versions with every decision and explain missing inputs with typed refusals.

**Permitted scope:** the relevant modules under `src/`, component-local tests/fixtures,
and their documentation. Add dependencies, runtime wiring, or migrations only when the packet
requires them and its owner has reviewed the design. Do not copy sibling implementations.

**Acceptance:** Replay the same recorded input bundle to the same decision. Unknown manifest, missing mandatory lineage, wrong tenant, and policy evaluation failure cannot allow. No target call or credential is needed for this packet.

**Handoff:** retain commands, exit codes, fixture/contract revisions, limitations and the
diff for review. A test specification is not a passed test. Publishing, deployment, live
provider calls, signing changes and policy activation are separate operations.

## Subsequent packets

| Packet | Implementation scope | Exit condition |
|---|---|---|
| GATE-02 | Implement the shared durable claim/journal protocol with Server and Warden. | Concurrent consumption, stale-worker fencing, and crash-before/after-dispatch tests pass against durable storage. |
| GATE-03 | Wire one disposable connector and Council's request-bound approval. | Substitution, expiry, revocation, changed target state, and required-recording failure block dispatch. |
| GATE-04 | Add reconciliation and a separately governed compensation path. | A lost response preserves unresolved state across restart; lookup does not repeat the effect. |

Each packet gets a concrete component issue and links to the coordinating hub issue when
execution begins. The identifiers above are local planning references, not claims that remote
issues or approvals already exist. Work advances one coherent capability slice at a time.

## Integration and operational readiness

Before any runtime capability is advertised, document its supported contracts, immutable source
revision, accepted dependency versions and deployment boundary. Demonstrate relevant failure
paths from [Validation](validation.md), then add the component runbook: required identities,
health and dependency states, migration order, backup/restore, key rotation where applicable,
and unresolved-work investigation.

A component result alone is not platform qualification. The hub's
[delivery sequence](https://github.com/iokaio/munarium-platform/blob/main/docs/build-plan.md) requires composition evidence, including the
Server/Matrix foundation and the authority path required by the selected consequence class.
Real enterprise connectors, gRPC, multiple policy evaluators, and production dispatch before the complete authority path is qualified.

## Completion criteria for the first functional increment

- The documented local recipe works from a clean clone using bounded disposable inputs.
- The acceptance cases are executable, retain their intended oracle, and include refusal paths.
- Unsupported operations remain explicit; logs and reports expose no credentials or private data.
- The README links the actual evidence before any capability or release label changes.
