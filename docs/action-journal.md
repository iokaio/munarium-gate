# Experimental PostgreSQL action journal

The owner-local API in [action_journal.rs](../src/action_journal.rs) implements
storage for hub [ADR 0014](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0014-stage2-service-integration.md).
It uses the same qualified cell row lock as activation. This is a tested storage
boundary, not an authenticated action execution endpoint. Stage 1 decisions and
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
hour rollover, expiry, restart and activation. This increment has no settlement
API: it cannot refund exposure from a timer, cancellation or guessed outcome.

`action_cancel` retains a bound tombstone even before a claim exists, serializing
against consumption. Because final admission is unavailable, cancellation reports
`cancelled`; it leaves prior consumption and reservations intact. A future final-send
adapter must add the shared-lock `too-late` outcome before enabling any send.
These methods take trusted local arguments, not deserialized HTTP authority.
Council withdrawal is not yet wired to this storage API.

`action_lookup` returns retained custody and `execution_enabled:false`.
`action_pending` and `action_ack` expose ordered exact outbox custody; a later
acknowledgement cannot skip an unacknowledged predecessor. Delivery of action
events through a service adapter is separate from participant `flush`.
No result from this API authorizes execution.

Run the actual PostgreSQL tests with an isolated `GATE_TEST_DATABASE_URL`:

```console
cargo test --offline --locked --test activation -- --ignored
```

CI explicitly selects these tests alongside the existing native activation tests.
They cover competing claims/workers, capacity races, pause/cancellation, exact
retry, atomic rollback, ordered acknowledgements, tenant isolation and restart.
The unchanged candidate bundle remains experimental. Live Council eligibility,
Warden issuance/custody, final-send response, target fencing, restore quarantine
and Linux isolation must be integrated and tested before opening execution.
