# Munarium Gate implementation architecture

**Proposed design; scaffold only.** Based on section 8 of the
[platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), with lifecycle and failure rules in
sections 17–19 and 22. See the hub's
[scaffold decision proposal](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0001-scaffold-boundaries.md)
for the distinction between local interfaces and normative contracts.

## Responsibility and current boundary

Deterministic decisions, durable execution claims, and isolated connector dispatch. Gate belongs to the **mediation plane**.
The crate declares interfaces only: no concrete implementations, serialization,
network listeners, persistence, service authentication or target operations exist.

The associated input, output and error types are intentionally unspecified.
These are proposed in-process seams for implementation work, not a released Rust API
or a second definition of the shared wire contract. A trait signature does not enforce
the trust assumptions below. Async runtime, transport and storage choices remain open.

## Module map

| Source | Proposed interface | Responsibility |
|---|---|---|
| [evaluation](../src/evaluation.rs) | `Evaluator` | Enrichment occurs before evaluation. Implementations must not make unrecorded network calls or manufacture permission when a required input is missing. |
| [journal](../src/journal.rs) | `ClaimJournal` | Atomic acquisition, grant consumption, fencing, and recovery require a jointly reviewed storage protocol; this port provides none of those guarantees yet. |
| [connector](../src/connector.rs) | `Connector` | Only an isolated host may supply the target credential. Unknown remote outcomes remain unresolved; this interface supplies no retry helper. |

## Planned flow and state ownership

Authenticate and validate → resolve Registry manifest → gather pinned inputs → evaluate → record decision → satisfy Council obligations → persist claim → obtain Warden grant → acquire/fence claim and consume grant → dispatch in isolated connector → append receipt or unresolved outcome.

Own the execution journal, worker ownership, and connector recovery state under the agreed protocol. Server is the authoritative accountability record. Journal acknowledgements and Server event linkage must be designed together; no second competing history or exactly-once external-effect promise.

## Dependencies and failure behavior

| Dependency | Required input or service | Failure rule |
|---|---|---|
| Registry | Verified manifest and effective activation context | Refuse missing, incompatible, stale, or revoked capabilities. |
| Warden | Verified principals, claim-bound grants, current revocation state | No new grant means no new granted dispatch. |
| Council | Bound approval when obligations require it | No new approval while unavailable; existing authority still needs all final checks. |
| Server / S2 and S9 | Required records and shared durable execution protocol | Required-recording failure stops new consequential dispatch. |

No dependency is linked into this scaffold. Supported contract versions are **none**.
Future adapters must consume a reviewed, versioned contract and identify its digest;
a floating hub branch is design context, never deployment authority.

## Threat assumptions

Treat agent code, supplied content and self-reported identity as untrusted.
Host administrators, release roots and required signing authorities remain explicit
trust assumptions of a qualified deployment. Process separation alone does not prove
independent administration.

| Threat | Required control to implement and test |
|---|---|
| Compromised agent and request substitution | Compute the validated canonical hash in Gate; recheck authority and target state before dispatch. |
| Worker races and lost responses | Durable claim, atomic grant consumption, fencing, and explicit unresolved recovery. |
| Compromised connector or redirect | Separate privilege domain, scoped target identity, bounded egress, payload and attachment checks. |

The [validation specification](validation.md) connects these requirements to the hub
invariants. No test evidence is implied by this design.

## Decisions needed before implementation

Choose one evaluator through a hub spike; settle canonicalization and the claim/grant transaction protocol; decide S9 library ownership with Server before writing journal storage. REST comes before additional transports; MCP must preserve native semantics.

A cross-component semantic change starts in a hub decision record. Keep publication,
activation and component implementation separate. Use expand, migrate, remove for
future breaking contract changes; never duplicate hashing, identity or grant rules.

## Deferred scope

Real enterprise connectors, gRPC, multiple policy evaluators, and production dispatch before the complete authority path is qualified.

The [implementation plan](implementation-plan.md) sequences the first useful increment.
No deployment recipe, service port or live-provider configuration is supplied at this stage.
