# Experimental Stage 2 activation barrier

Gate implements the participant protocol in hub
[ADR 0014](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0014-stage2-service-integration.md).
The candidate remains unchanged and unaccepted:
`8aca66588c87107a0c7a7720c68f921dfd2bdcaecf6433728afa4b1c51420aa6`.
Council baseline is `6ea0822`, Registry `eb08f75`, hub `27c3e6c`.

## Service configuration and authority

The existing service configuration accepts an optional `activation` object with
`database_url_file` (absolute path to an operator-owned PostgreSQL connection URL)
and `council_endpoint` (HTTPS base URL). Existing Server, Registry and Warden
endpoints and the mTLS client identity are reused. Keep the URL file outside Git;
errors never print it. Omitting this object leaves activation unavailable and
preserves Stage 1 decisions. There is no action source, cancellation, claim,
grant consumption or final-send endpoint in this increment.

The current Server governing artifact must contain `stage2:<Gate service>`:

```json
{
  "scope": {"domain":"example","tenant":"tenant-a","deployment":"lab","cell":"cell-a"},
  "coordinator":"council",
  "readers":["registry","server","warden"],
  "initial_epoch":1,
  "initial_artifact_set_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

This is an illustrative binding shape, not an activated artifact or usable initial
artifact set. The existing non-agent governing ceremony must admit actual inputs.
The enrollment pins the initial head once; subsequent config cannot reset it.
Each caller needs an enrolled mTLS certificate and tenant mapping. Only the exact
coordinator service can mutate; readers can inspect receipts and the current head.
No agent-supplied identity or forwarded header establishes authority.

POST `/v1/actions` takes `{"tenant":"tenant-a","action":{...}}`:

| Operation | Additional fields | Result |
|---|---|---|
| `pause` | `transition`: canonical activation JSON string | Durable original Gate pause receipt |
| `pause-lookup` | `transition_id` | Historical pause receipt, without pausing anything |
| `apply-activation` | `transition` | Original Gate applied receipt; remains paused |
| `activation-lookup` | `transition_id` | Historical applied receipt |
| `activation-head` | none | Current scope, epoch, set, transition and paused status |
| `resume` | `completion`: exact transition, pause and four applied receipts | Bound resume result with `execution_enabled:false` |

Mutations independently query Council for current exact ratification and enforce
the two-second clock bound. Resume additionally retrieves Registry, Server and
Warden receipts and heads directly over mTLS. Missing, changed, duplicated or stale
evidence refuses. A governing revision change during lookups also refuses.
Server's participant route is implemented in Server PR #77. Its absence or a
mismatched receipt still keeps this barrier closed.

## Persistence and recovery

The additive [migration](../migrations/0001_activation.sql) creates Gate-owned
PostgreSQL tables. Startup serializes schema installation with a transaction-scoped
advisory lock. Operational mutations lock the qualified cell row. Pause, epoch
installation and resume each commit with a retained local outbox record. Concurrent
transitions sharing a prior head have one winner. Initial admission is paused.
Future consumption and final-send transactions must use the same scope row lock.

Receipt retries recover exact committed bytes; conflicting content refuses.
Historical receipt lookup cannot reopen a later transition. An interrupted
coordinator retries the same phase and transition while its ratification is current.
Expired or revoked authority remains refused and paused; an administrative repair
ceremony for a stranded transition is not implemented here.

The outbox retains local phase records; delivery as acknowledged Server
accountability events is still required. No restore quarantine, external recovery
epoch, target-floor protocol, target effect or execution availability is claimed.
Process restart preserves this store; restoring an older snapshot is a different,
currently unsupported operation. Do not use this increment to enable dispatch.

## Reproduce the component checks

Run the repository Rust gates, then point `GATE_TEST_DATABASE_URL` at a disposable,
empty PostgreSQL database and run:

```console
cargo test --offline --locked --test activation -- --ignored
python scripts/test_activation_service.py -v
```

The first command explicitly selects real PostgreSQL race/restart tests. It fails
if the URL is absent; the ordinary suite labels these cases ignored. The native
test launches the actual Gate binary, kills/restarts it, and exercises disposable
mTLS against synthetic Council/Registry/Server/Warden dependencies. It checks
transport enrollment, coordinator/reader separation, tenant refusal, retained
receipts and incomplete barrier refusal. It does not run the evaluator or targets.
CI runs both commands using pinned PostgreSQL and retains the existing Windows
evaluator job. SQLx core/PostgreSQL are pinned together at 0.8.6 because their
internal APIs are version-coupled; the umbrella crate conflicts with existing
SQLite native linkage.

Observed local image: `postgres@sha256:65b16a8b326e0cfbdf33fa7e783f2a0cb352a61448616ccccfd616ef42aa0f65`.
Tests used one task-owned loopback container, 384 MiB/one CPU, synthetic credentials,
and a disposable database. Owner: the maintainer's local test session; availability:
cached image and Docker verified before launch; no paid resources; expiry: task
teardown. Native test keys and SQLite files expire with each temporary directory.
Full Linux service isolation, REF-18 and snapshot restoration remain unqualified.

## Participant audit delivery

The coordinator may POST `flush` to the existing activation route (Gate uses
`/v1/actions`). Each call delivers at most one pending applied receipt. A reader
cannot flush. The response reports `delivered:1` with the exact Server
acknowledgement, or `delivered:0` when no intent remains pending. Retry until zero;
dependency failure or an invalid acknowledgement keeps the oldest event pending.
Expiry of the transition does not invalidate historical delivery authority.
Current Server identity/stream admission still applies to every append.

Add the optional top-level service configuration `delivery` with `server_service`,
`warden_endpoint` (an HTTPS origin), `provider_id` and absolute
`provider_token_file`. The file is operator-supplied and never logged. Warden's
provider enrollment must bind the actual service peer to the Server audience,
`propose` scope and `action-records:<tenant>` resource. Server must enroll this
peer for recording and admit its current identity in `identity:<Server service>`.
No caller assertion or forwarding header supplies the recorder identity.

The current `action-records:<Server service>` binding must register exactly one
stream for this service/producer with only `activation-applied` in `kinds`.
Source generation and stream are pinned by the first materialized event. A changed
registration refuses rather than rewriting pending history or guessing a new
sequence. The stream must be dedicated to this owner database.

Operational receipts and intent remain atomic. Additive delivery tables retain
canonical event bytes before sending, then the exact acknowledgement after closed
schema, event/payload hash, qualified scope and ledger-position validation. The
event timestamp is the first durable delivery observation. A lost response retries
the same event, source sequence and timestamp; concurrent flushes are duplicates,
not new facts. Receipt intent remains retained after acknowledgement. Server must
already hold the Council transition, normally archived by Server's participant
apply. Gate pause/resume history has no invented candidate event type.

This is audit delivery, not execution admission or snapshot reconciliation. Missing
source history and changed generations fail closed. Component restart/negative
acknowledgement tests and Harness's real-service delivery test exercise this path.
No production trust, target effect or recovery qualification is claimed.
