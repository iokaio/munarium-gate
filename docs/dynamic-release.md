# Experimental dynamic release materialization

The [materializer](../src/dynamic_release.rs) implements the first bounded part of
[ADR 0016](https://github.com/iokaio/munarium-platform/blob/74fffdf67d7911f62eec3650fc0a8e9d7ec42239/docs/decisions/0016-dynamic-release-admission.md).
It accepts typed trusted owner inputs and agent parameters, validates their exact
bindings, derives the admitted test-result evidence and evaluates a pinned engine.
It does not authenticate callers. The experimental service adapter independently
verifies owners, live activation heads and current peers before constructing these
inputs. Full real-service dynamic action composition remains subsequent work.

The supported operation is a C2 disposable publication with a distinct approval,
no attachments or modifiers and an unchanged enrolled destination. Manifest, policy,
parameter schema and evaluator profile hashes must match. Current enrolled requester
identities, scoped context, validity and evidence hash/derivation/type/freshness are
mandatory. Test-result source bytes come from Server-signed enrollment; arbitrary
retrieved or agent-provided evidence is unsupported. Policy has the closed profile
`stage2-release-evaluation-v1`, engine/version/binary/worker/capability pins, Rego code,
parameter schema and distinct-approval rule mappings.

The closed result requires allow/forbid booleans, unique admitted determining rules,
supported predicates and no diagnostics. Any forbid wins. A permit becomes
approval-required with all four mandatory controls: distinct approval, recording,
capacity and credential custody. A denial has no executable obligations. The exact
request, context and decision digests are computed in Gate.

The [journal lookup](../src/final_send.rs) retrieves immutable source bytes after
restart, verifying request/decision, operation, attempt and context bindings. It never
replaces corrupted content, creates an approval/grant or emits send permission.

## Verification and limits

```console
cargo test --offline --locked --test dynamic_release
cargo test --offline --locked --test activation -- --ignored
```

The first command uses a typed fake engine to prove semantic binding, parameter/
owner substitutions, freshness/lineage failures, mandatory obligations, forbid
precedence and malformed native-result refusal. It is not native OPA evidence.
The second requires an explicitly isolated PostgreSQL database and includes source
reopen, immutable conflict, tenant refusal and corrupt-binding controls, alongside
the existing real journal/activation tests. Existing Windows/Linux native evaluator
controls remain independent. Full dynamic request-to-effect composition, broader
evidence/task profiles and safe restore reopening remain unqualified.

## Experimental service adapter

`POST /v1/actions` adds `propose` with enrolled `operation_id`, `attempt_id` and
closed `parameters` (`artifact_digest`, `destination`). Duplicate or authoritative
fields refuse. Current Server-signed task enrollment supplies optional `evaluation`
with canonical `evidence_source`; the existing request field becomes its immutable
context/task template. Without that enrollment, `propose` refuses and the prepared
API remains compatible. Dynamic entries cannot use `prepare` to bypass evaluation.

Gate obtains its own current Warden assertion, resolves the Registry-verified exact
manifest, verifies Registry's installed head and resolves the current policy from
its signed artifact registration. It checks native pins, evaluates outside async
executor threads, rechecks authority, validates exact Server archive receipts and
persists the immutable source. Retries/readers return original bytes. Claims,
consumption and final admission use that source with current context, retirement
and owner checks instead of reevaluating or renewing authority.

The additive native Linux service test uses the real Gate/OPA/PostgreSQL with
explicitly synthetic authenticated Server, Warden and Registry dependencies. It
tests actor/tenant/parameter refusal, wrong archive custody, restart/retry, source
lookup and retirement. This is component integration; it creates no target effects
and does not replace the actual five-service/agent/target composition.
