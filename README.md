# Munarium Gate

**Policy decision and enforcement point for every tool call.** Gate is the mediation-plane
component of the Munarium Governance Platform through which an agent's proposal to create an
external effect must pass. It resolves the signed manifest, validates the canonical request,
verifies the principal chain, computes the consequence class, decides, records a durable execution
claim, and hands the approved request to an isolated connector that holds the credential the agent
never sees. Gate is the largest of the nine new components and the platform's main technical risk.

> **Status: Stage 1 decision service implemented.** The authenticated service/client
> profile is implemented and covered by component and separate-process tests.
> See the [service profile](docs/service-profile.md). Candidates remain inactive;
> no execution endpoint is mounted. Human acceptance and production qualification
> remain pending.

Gate is one of nine components built around the existing Munarium foundation, Munarium Server and
Munarium Matrix. Their shared architecture, normative contracts, decision records, roadmap and
composition evidence live in the public hub,
[iokaio/munarium-platform](https://github.com/iokaio/munarium-platform). This repository will hold
Gate's implementation, its unit and component tests, the migrations it owns, operational
diagnostics, package definitions, a local development recipe and release evidence. It is open
source from its first public commit, under the Apache License 2.0, with no proprietary edition.

## Start building

Read the [development index](docs/README.md), then the [architecture](docs/architecture.md),
[implementation plan](docs/implementation-plan.md) and [validation guide](docs/validation.md).
They map the public platform plan to source modules, dependencies, a first bounded work item
and acceptance cases. See the experimental [Stage 1 implementation](docs/stage1.md).
Released supported contract versions remain **none**.

## What Gate is for

The platform separates four powers: **read**, **governed write**, **act** and **govern**. Gate is
where *act* is decided and enforced. An agent may propose an external action without possessing the
target credential; a service may execute an approved request without holding the power to approve
a broader one. Agent code is untrusted: Harness and prompts provide convenience, and enforcement
resides here, outside the agent process and privilege domain. A direct credential, network route,
shell or vendor connector outside Gate's mediation is a documented bypass, not a governed path.

Gate does not make models infallible and does not control unmediated paths. Its guarantee is
deliberately conditional: within a qualified deployment, the specified consequential path is
mediated, and the agent cannot acquire authority through that path that the deployed controls deny.

## The design, as planned

Gate is developed as three explicit subsystems. They may share this repository; they must not
share unrestricted privileges for convenience.

### 1. The decision engine

The engine resolves the signed manifest, validates the canonical request, verifies the principal
chain, enriches the request with recorded context, computes the consequence class, and returns
**allow**, **deny** or **approval-required** with obligations. An unavailable mandatory input is not
replaced by the model's explanation of what it probably contains.

- **One policy evaluator in the first release.** A short implementation spike compares required
  policy expressiveness, determinism controls, schema handling, integration cost, resource limits
  and testability across the candidates (the source architecture favored Cedar and OPA/Rego), and a
  hub decision record names the chosen engine and version. The language name alone is not proof
  of correctness.
- **Enrichment is separate from evaluation.** A current entitlement, verified vendor record,
  classification label or change-freeze flag is retrieved through an authenticated source and
  retained in the input bundle with its source version and freshness. The evaluator receives those
  inputs; it makes no unrecorded network calls during the decision.
- **Decisions are reproducible.** Replay uses the same recorded inputs, policy bundle, engine
  version and contract semantics. Re-running a model with the same prompt is not policy replay.

### 2. Durable execution

An allowed decision is not an execution. Gate first records the proposal, the decision, the
satisfied obligations and a **durable execution claim** that binds tenant, semantic operation
identity, target, canonical request hash and approved execution scope. Warden may then issue a
grant for that claim.

- The execution worker **atomically acquires the claim and consumes the grant**. Parallel workers
  cannot each treat one grant as unused; a fencing value prevents a worker that lost its lease from
  dispatching after another has taken over. Recovery tests cover crashes before dispatch, after
  dispatch, and before receipt persistence.
- **Exactly-once external effects are not promised.** A remote system can apply a request and lose
  the response. Gate preserves that ambiguity as an **unresolved** state and stops blind
  repetition. A target's idempotency support, with its documented scope and retention, is part of
  the connector contract.
- **Required-recording failure stops new dispatch.** If an outcome becomes known while the ledger
  is unavailable, the qualified connector or execution journal preserves it through the supported
  durable recovery path; it never invents a successful ledger write.

### 3. The isolated connector host

A connector may receive the narrow credential needed to execute an approved request. **The agent
must not.** Connectors run with separate identities and bounded network access, grouped by target
and credential domain. The initial reference connector targets a disposable local service so that
fault injection never endangers real records.

- Generic shell, unrestricted HTTP, arbitrary SQL and unbounded file-writing tools are never
  exposed as low-risk capabilities. A development sandbox may contain a shell; that shell carries
  no production authority.
- Connector execution constrains redirects, target resolution, payload size, attachment references
  and environment selection. A request approved for one endpoint must not follow an
  attacker-controlled redirect to another with the same credential. **Target identity is part of
  authorization**, not a transport detail.

### Interfaces

The **native Action API is the canonical contract**. MCP is an adapter to that contract, not a
privileged second execution path; the adapter follows the MCP authorization specification and
rejects inappropriate token forwarding. REST is the first direct interface; gRPC and further
transports follow only after shared semantics have contract tests.

### The governed action lifecycle

A governed action begins with a proposal, not a credential.

| Step | What happens | What is recorded |
|---|---|---|
| 1 · Propose | Typed tool and arguments from an authenticated principal | The proposal |
| 2 · Resolve | Pinned manifest, evidence and enrichment | The decision inputs |
| 3 · Decide | Allow, deny or approval-required | The decision, policy digest, evaluator version, consequence derivation, obligations |
| 4 · Authorize | Council approval where required, bound to the exact action | The approval and its execution window |
| 5 · Claim and grant | Durable execution claim; Warden-bound grant | The claim, then the grant |
| 6 · Dispatch | Isolated connector; no secret in agent context | Dispatch ownership |
| 7 · Reconcile | Target result and postconditions; unknown is not failure | The outcome, or unresolved |
| 8 · Record | Receipt and evidence links | The receipt |
| 9 · Recover | Investigate uncertainty; govern any compensation | A new, separately authorized action |

Mandatory evidence is not deferred to the end. Proposal and decision are recorded before any
effect-producing work; claim and grant precede dispatch; the outcome is appended when known. A
failure between stages leaves a truthful partial chain and a recoverable state.

**The proposal contract** carries identity (tenant, verified subject or service origin, agent
release, instance, delegation reference, all derived from authenticated context), capability (tool
identifier, manifest digest, explicit target, environment), typed arguments with a canonical
representation, evidence references with trust metadata, purpose (task and session identifiers;
free text is not permission), execution identity (a stable business-operation identity and
idempotency key, with a rule distinguishing a retry from a new intended action) and preconditions
(target state expectation, validity window, required freshness). **Gate computes the authoritative
request hash after validation; it never trusts a hash supplied by the agent.** Large payloads are
represented by verified content digests and controlled references, not mutable URLs.

**Hash binding does not freeze the world.** Before dispatch, Gate rechecks expiry, revocation,
relevant policy activation and target-state preconditions. An approved update whose target version
has changed fails or returns for new approval. These are freshness decisions, not evidence that
hashing failed.

**The execution state machine**: proposed → denied | approval required | authorized and claimed →
dispatching → completed | unresolved → compensated or superseded. A retry with the same operation
identity and different canonical content is a conflict. An unresolved record does not expire into
permission to try again. A compensation is a new action with its own authorization and record, and
the manifest describes the actual compensation semantics rather than claiming universal
reversibility.

### Consequence classes and provenance

A class is computed from the approved manifest and verified context; an agent's description of an
action as harmless does not lower it. Modifiers raise the base class on amount, recipient,
environment, evidence quality, data classification or target state; they never quietly downgrade
it. Policy also carries cumulative limits.

| Class | Meaning within the qualified deployment | Default posture |
|---|---|---|
| C0 | Bounded observation with no restricted disclosure or target mutation | Scoped authorization and the declared record policy |
| C1 | Internal, bounded, ordinarily reversible change | Deterministic allow with limits and a receipt |
| C2 | Bounded external effect or more consequential internal change | Verified arguments, scope and cumulative limits, required provenance, receipt |
| C3 | Irreversible, highly sensitive, regulated or production-critical effect | Explicit distinct authority and satisfied obligations before execution |
| C4 | Prohibited for the requesting principal or deployment | No reachable authorized execution path |

A read can disclose sensitive data and is not automatically C0. Untrusted content must not become
authority by appearing in a model's context: source labels and derivation links are preserved,
missing lineage remains unknown, and for authority-bearing fields (a bank account, a recipient, a
production target, an approved artifact) Gate resolves the value from an authoritative record or
requires an exact, separately approved field binding. A loosely related citation is insufficient.

## First public increment

**Decision-only evaluation and replay against a fake target.** It reports clearly that no
production action path is qualified. The first effect-producing release requires the minimum
Registry, Warden, durable record and distinct approval path needed by the chosen consequence
class; a partially implemented Warden is not replaced by handing a service account to the agent.

Target window: Stage 1 (decision-only, months 2–3) and Stage 2 (the first complete governed action, months 4–6). The source architecture's 10 ms decision and 25 ms provenance p99 figures
are exploration targets, not launch promises; end-to-end measurements will state workload,
hardware, cache conditions, concurrency and required durable writes.

## Capability status

The labels are evidence labels, not editions: **Planned**, **Experimental**, **Conformance-tested**,
**Reference-qualified**, **Independently reviewed**. In the hub's component catalog this
repository is at **repository created**.

| Capability | Status | Evidence |
|---|---|---|
| Decision engine with privileged identity/Registry adapters and typed outcomes | Experimental | [Stage 1](docs/stage1.md), [tests](tests/decision.rs) |
| Bounded native OPA worker; formal engine acceptance pending | Experimental | [Worker and controls](docs/stage1.md#evaluator-profile) |
| Canonical request validation and hashing against unchanged candidate vectors | Experimental | [Tests](tests/decision.rs) |
| Deterministic decision replay from a pinned input bundle | Experimental | [Persisted replay](docs/stage1.md) |
| Fake-target execution lifecycle for tests | Planned | none |
| Durable execution journal: claim, grant consumption, fencing, crash recovery, unresolved state | Planned | none |
| PostgreSQL activation pause, epoch installation and complete-receipt barrier | Experimental | [Activation profile](docs/activation-profile.md), [tests](tests/activation.rs); no execution path |
| Isolated connector host with a disposable reference connector | Planned | none |
| Native Action API over REST | Planned | none |
| MCP adapter to the Action API | Planned | none |
| gRPC and further transports | Deferred until shared semantics have contract tests | none |
| Real enterprise target connectors | Deferred; each has its own conformance record | none |

Supported contract versions: **none**. Supported deployment profiles: **none**. Qualified action
paths: **none**. Experimental library operations are documented in [Stage 1](docs/stage1.md).

## Acceptance evidence for the first releases

Stage 1, decision-only: deterministic replay of allowed and refused proposals, unknown-manifest
rejection, tenant isolation fixtures, contract compatibility, and no hidden target credential in the
agent environment.

Stage 2, the first complete governed action, demonstrated with one narrow connector, one reference
identity system and one deployment profile:

| Test | Required outcome |
|---|---|
| A permitted effect | Completes with a recorded proposal-to-outcome chain and receipt |
| An unauthorized effect | Refused with a typed reason and a recorded decision |
| Request substitution after approval | Refused; a changed request is a new evaluation |
| A stale approval, expired window or changed target precondition | Refused before dispatch |
| Concurrent use of one grant | Exactly one dispatch; the other worker observes consumption |
| An invalid or self-reported principal chain | Refused |
| A policy error or missing mandatory input | Typed refusal, never permission |
| Mandatory-recording failure | No dispatch |
| Connector compromise simulation | Effects bounded to the connector's granted scope; secrets absent from agent-visible surfaces |
| Unknown target outcome | Unresolved state preserved; no automatic repetition |
| Crash before dispatch, after dispatch, before receipt | Recoverable, truthful partial chain |
| Attempted self-ratification | The active policy is unchanged |

A release is ready for a stated reference use case when an adopter can independently run its
conformance suite and reproduce both the allowed action and the prohibited alternatives. The
objective is not a demonstration that a friendly model follows the rules; it is evidence that the
tested path remains constrained when the request does not.

## Invariants

| ID | Required property | Owner and first gate |
|---|---|---|
| INV-03 | Every accepted action has a verified tenant and principal context | Warden, Gate, Server; stages 1–2 |
| INV-04 | Unknown or incompatible manifests fail closed | Registry and Gate; stage 1 |
| INV-06 | Missing mandatory lineage does not become trusted authority | Server and Gate; stages 1–2 |
| INV-08 | No grant is issued without a durable, matching execution claim | Gate and Warden; stage 2 |
| INV-09 | Approval is invalid after relevant content, policy validity or target preconditions change | Council and Gate; stage 2 |
| INV-10 | A grant cannot be concurrently consumed for multiple dispatches | Warden and Gate; stage 2 |
| INV-11 | An unresolved effect is never blindly repeated | Gate, connector, Harness, Console; stages 2–3 |
| INV-14 | Required-recording failure prevents new consequential dispatch | Server, Gate, Gateway; stages 2–3 |
| INV-20 | A local overlay cannot waive a mandatory parent prohibition | Council, Registry, Gate; stage 5 |
| INV-22 | A release advertises only the profiles and capabilities supported by its evidence | every component; every stage |

## Contracts, dependencies and neighbors

- **Contracts.** The hub's contracts directory is normative for the Action Proposal, decision,
  claim, grant, receipt and compensation shapes, the canonicalization specification and its
  cross-language golden vectors, and the outcome vocabulary. Gate implements them. Supported
  contract versions: none yet.
- **Foundation.** Munarium Server 1.3.0 provides the durable record; the hub's S2 (linked
  action-record shapes) and S9 (a reusable owner-maintained guarded-execution library) are the
  Server changes Gate depends on, so that the execution journal has one owner rather than
  slightly different copies in Gate and Server. Munarium Matrix 1.2.0's governed reads are the
  precedent for Gate's narrow tools.
- **Registry** supplies signed manifests; **Warden** issues request-bound grants and brokers
  connector credentials; **Council** supplies approval where the consequence class requires it;
  **Harness** is the client; **Sentinel** reads Gate's records; **Console** explains its
  decisions.
- **External dependencies.** See [Cargo.toml](Cargo.toml), the lockfile and
  [dependency notices](THIRD_PARTY_NOTICES.md). Stage 1 choices remain experimental.

## Not in scope

- Exactly-once external effects, or automatic retry of anything unresolved.
- Trusting an agent-supplied hash, consequence class, or lineage claim.
- Two primary policy evaluators in the first release.
- Generic shell, HTTP, SQL or file tools as low-risk enterprise capabilities.
- Real enterprise targets before their connector's own conformance record exists.
- Claims about latency, throughput or bypass-freedom that the published measurements and the
  declared control boundary do not support. Discovery and tests locate gaps; they do not prove
  that every possible bypass has been eliminated.

## Roadmap position

| Stage | Gate's part |
|---|---|
| 0 · month 1 | This repository; the canonicalization and action-record contracts drafted in the hub |
| 1 · months 2–3 | Decision-only evaluator, replay, fake target, canonicalization vectors, policy-engine decision record |
| 2 · months 4–6 | Durable journal, Warden grant consumption, Council approval path, one narrow connector: the first complete governed action |
| 3 · months 7–9 | Daily use on bounded development tasks; denial explanations through Console; Sentinel timeline |
| 4 · months 10–12 | Inclusion in the reference composition, restore and stale-worker fencing exercises, evidence packs |
| 5 · months 13+ | Further connectors, transports and federation constraints, demand-led and separately qualified |

Request binding, mandatory evidence, credential isolation and required distinct authority are never
removed to preserve a date.

## Repository layout

| Path | What exists |
|---|---|
| [Cargo.toml](Cargo.toml), [Cargo.lock](Cargo.lock) | Independent library, version 0.1.0-dev, publishing disabled, reviewed locked dependencies |
| [src/lib.rs](src/lib.rs) | Experimental decision implementation and proposed later-stage interfaces |
| [docs/](docs/README.md) | Architecture, implementation sequence and acceptance specifications |
| [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md) | Contribution process and aligned development guidance |
| [.github/workflows/](.github/workflows/) | Automatic Rust, repository-hygiene and DCO checks |
| [scripts/](scripts/), [check_license.py](check_license.py) | Existing documentation, private-material and license checks |
| [LICENSE](LICENSE), [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Licensing and dependency notices |

Subsystem modules: [evaluation](src/evaluation.rs), [journal](src/journal.rs), [connector](src/connector.rs).
Stage 1 tests and candidate fixtures are implemented. The ordinary component build depends on
no sibling checkout; Harness owns the separate experimental composition.

## Development

Use Rust 1.98.1 with rustfmt, Clippy and the platform's native linker. From this repository root:

```console
cargo fetch --locked
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

The [Stage 1 guide](docs/stage1.md) names the implemented tests and remaining coverage.
The [validation guide](docs/validation.md) retains the broader acceptance specifications.

Also run the existing hygiene gates:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` where `py` is unavailable. The new
[Rust workflow](.github/workflows/rust.yml) runs on main pushes and pull requests alongside
the existing [repository hygiene](.github/workflows/repo-hygiene.yml) and
[DCO](.github/workflows/dco.yml) workflows. They provide build and repository checks, not a
qualified runtime. No package is published or service deployed by these workflows.
Local checks do not imply hosted CI success. See [CONTRIBUTING.md](CONTRIBUTING.md).

## The platform

| Repository | Plane | Role |
|---|---|---|
| [iokaio/munarium-platform](https://github.com/iokaio/munarium-platform) | hub | Architecture, normative contracts, decision records, roadmap and composition evidence for the whole platform |
| [iokaio/munarium](https://github.com/iokaio/munarium) | foundation (mediation) | Munarium Server: governed memory, the append-only ledger, and the Server client libraries |
| [iokaio/munarium-matrix](https://github.com/iokaio/munarium-matrix) | foundation (mediation) | Munarium Matrix: governed, read-only structured evidence from enterprise data sources |
| [iokaio/munarium-registry](https://github.com/iokaio/munarium-registry) | authority | Inventory of agents, tools, manifests, and policy bundles |
| [iokaio/munarium-harness](https://github.com/iokaio/munarium-harness) | agent | SDKs that make the governed path easy for honest agents |
| [iokaio/munarium-warden](https://github.com/iokaio/munarium-warden) | authority | Workload identity, delegation, just-in-time credentials, kill switches |
| [iokaio/munarium-gate](https://github.com/iokaio/munarium-gate) | mediation | Policy decision and enforcement point for every tool call |
| [iokaio/munarium-gateway](https://github.com/iokaio/munarium-gateway) | mediation | Model-call mediation: routing, BYOK, budgets, screening |
| [iokaio/munarium-council](https://github.com/iokaio/munarium-council) | authority | Approvals, policy lifecycle, ratified governance transitions |
| [iokaio/munarium-sentinel](https://github.com/iokaio/munarium-sentinel) | assurance | Telemetry, anomaly detection, circuit breakers, incident replay |
| [iokaio/munarium-assure](https://github.com/iokaio/munarium-assure) | assurance | Control-framework mapping and evidence packs |
| [iokaio/munarium-console](https://github.com/iokaio/munarium-console) | assurance | One interface for approvers, operators, and auditors |
| [iokaio/munarium-clients-publish](https://github.com/iokaio/munarium-clients-publish) | tooling | The one place Munarium client packages are built for release and published from |
| [iokaio/munarium-demo](https://github.com/iokaio/munarium-demo) | examples | Munarium Demo: working applications and bundled datasets for evaluating the foundation |

The development tool VCP ([iokaio/vcp](https://github.com/iokaio/vcp)) is separate: not one of the
nine components and not a runtime dependency for adopters. Ioka's private repositories hold
planning material awaiting publication review and the proprietary Matrix analytics adapters;
nothing from them is copied into a public repository without that review.

## Licensing

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The names are not part of that grant:
[TRADEMARK.md](TRADEMARK.md) says what you may do without asking, which is most things. There is
no proprietary edition of this component and none is planned; a capability that arrives later is
deferred roadmap work, not a commercial restriction.

## Contributing, support, security

Signed-off pull requests, no CLA ([CONTRIBUTING.md](CONTRIBUTING.md)). Questions go to Discussions,
defects and design findings to Issues, and suspected vulnerabilities to the private channel
[SECURITY.md](SECURITY.md) names, never a public issue. What is and is not supported:
[SUPPORT.md](SUPPORT.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Release history,
such as it is: [CHANGELOG.md](CHANGELOG.md).

The experimental [PostgreSQL action journal](docs/action-journal.md) now provides
atomic claim, cancellation, consumption, capacity and audit storage. Participant
outboxes support authenticated Server delivery. Execution remains unavailable.
