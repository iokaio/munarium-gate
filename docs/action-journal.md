# Experimental PostgreSQL action journal

The owner-local API in [action_journal.rs](../src/action_journal.rs) implements
storage for hub [ADR 0014](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0014-stage2-service-integration.md).
It uses the same qualified cell row lock as activation. This is a tested storage
boundary, connected to the opt-in prepared release adapter below. Stage 1 decisions and
the provisional `ClaimJournal` trait remain compatible.

`action_enroll` pins a dedicated action source stream/generation once.
`action_claim` validates closed request/decision/approval/event records, hashes,
scope, bounded validity and exact custody evidence. It requires an unpaused matching
activation epoch for a new claim, and atomically stores the immutable binding,
claim and canonical `claim-created` outbox event. Changed operation or attempt
bindings conflict; the same retry retains the original claim. This increment
conservatively refuses new attempts under an already claimed operation. Attempt
closure and evidence-based reopening are later work.

`action_consume` accepts trusted, independently verified Warden issuance and
worker inputs. It verifies exact claim/grant bindings and custody acknowledgement,
then under the same cell lock checks pause/cancellation, reserves every limit,
consumes one grant, binds one worker/fence and appends `consumption-reserved` and
`predispatch` events in one PostgreSQL transaction. A changed worker cannot take
over. Fence one is scoped to the immutable claim; no takeover or second send
opportunity exists. Any failure rolls back all writes. An identical retry returns
the original consumption, without a new reservation, fence or event.

The mandatory target bucket permits two publication admissions per qualified
tenant/cell/target UTC hour. Additional trusted policy buckets are conjunctive
and locked in sorted order. Every unresolved reservation remains charged across
hour rollover, expiry, restart and activation. Independent completed-effect
reconciliation settles unresolved exposure while retaining the original hour's charge.
Timers, cancellation and a connector's own report cannot refund exposure.

`action_cancel` retains a bound tombstone even before a claim exists, serializing
against consumption and final admission. It reports `cancelled` before final admission
and `too-late` afterward, leaving prior consumption and reservations intact. The
authenticated adapter returns Council's exactly bound withdrawal receipt. These
storage methods take trusted local arguments, not deserialized HTTP authority.

`action_lookup` returns retained custody and `execution_enabled:false`.
`action_pending` and `action_ack` expose ordered exact outbox custody; a later
acknowledgement cannot skip an unacknowledged predecessor. Delivery of action
events through a service adapter is separate from participant `flush`.
Historical lookups and outbox delivery never authorize execution.

Run the actual PostgreSQL tests with an isolated `GATE_TEST_DATABASE_URL`:

```console
cargo test --offline --locked --test activation -- --ignored
```

CI explicitly selects these tests alongside the existing native activation tests.
They cover competing claims/workers, capacity races, pause/cancellation, exact
retry, atomic rollback, ordered acknowledgements, tenant isolation and restart.
The unchanged candidate bundle remains experimental.

## Prepared synthetic release service

The adapter in [execution_service.rs](../src/execution_service.rs) requires a current
Server-signed `execution:<service>` binding: qualified `scope`, enrolled `council`,
`warden`, `connector`, `readers`, dedicated `stream`/`generation`, external `recovery`
generation and immutable `requests`. Each request maps an operation to `proposer`,
`request` and complete `requester_chain`. The caller selects an enrolled operation;
Gate computes its hashes and fixed mandatory obligations. This is an explicitly
operator-prepared disposable release surface, not arbitrary agent parameters or a
claim that a Linux OPA evaluator ran. The activation set must match. Governing
request changes conflict with retained source/claim identity.

`POST /v1/actions` adds `prepare`, `source`, `claim`, `claim-lookup`, `consume`,
`action-flush`, `final-send`, `unresolved`, `reconcile` and Council-only `cancel`.
Inputs are closed; only the enrolled proposer prepares, the connector claims,
consumes and requests final send, and readers reconcile. Gate independently fetches
Council status/acknowledgement and Warden issuance/custody. It rechecks Server
authority after dependent calls. `prepare` archives request and decision before
approval; action outboxes preserve exact ordered Server custody.

[final_send.rs](../src/final_send.rs) requires live custody no longer than five
seconds, exact consumed worker/fence/grant and stored predispatch acknowledgement.
The cell transaction checks cancellation, pause, epochs and expiry, appends send
intent and consumes the sole send opportunity. Only the successful first live
response has `send_permitted:true`. Lost replies, duplicate requests, new processes
and lookup results never create replacement permission. Target-side fencing is
still necessary for a worker paused after admission.

Optional local configuration `execution.target_endpoint` pins the authenticated
synthetic target's read-only observation endpoint. `reconcile` fetches completed
effect evidence there; callers cannot supply a receipt. It verifies operation,
request, target, effect key, recovery/fence, result content and next target version,
then appends reconciliation while preserving the original outcome. No-effect
settlement and compensation are unavailable.

Recovery generation enrollment is immutable. A newly governed external generation
refuses old storage; no `resume` boolean reopens it. Restore procedures must advance
external authority and install the target floor before bringing restored workers
online. The current adapter does not automatically detect an undisclosed database
rollback or implement cutoff reconciliation/reopening. Historical audit delivery
does not gain execution authority. Harness tests a real pre-effect PostgreSQL
snapshot restored into a new isolated database with retained Server/target state.
OS network/secret isolation and production qualification remain separate requirements.
