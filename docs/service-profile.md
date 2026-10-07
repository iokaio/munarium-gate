# Stage 1 decision service

Build `cargo build --locked` and run `munarium-gate ABSOLUTE_CONFIG_PATH`.
The closed JSON configuration names `tls`, `server_endpoint`, `registry_endpoint`,
`warden_endpoint`, `deployment`, recipient `service`, `server_service`,
`registry_service`, `provider_id`, protected `provider_token_file`, absolute SQLite
`journal` and `evaluator`. All outbound URLs use HTTPS without proxies or redirects.

`tls` contains `listen`, PEM `certificate_file`, `private_key_file`, `ca_file` and
`peers`, mapping lowercase SHA-256 client leaf fingerprints to `{service, tenants}`.
`evaluator` contains `python`, `worker`, `executable`, their `worker_digest` and
`executable_digest`, engine `version` and pure `capabilities`. The supported native
profile and resource limits are specified in [Stage 1](stage1.md).

`POST /v1/decisions` accepts `{tenant, chain, action}`. Actions are:

- `{operation: "submit", request}` with the exact canonical proposal as a string;
- `{operation: "lookup", operation_id}` for a read-only recorded result;
- `{operation: "replay", operation_id}` to reevaluate immutable archived inputs.

Gate independently obtains current authority, verifies the caller's actual mTLS
presenter and signed chain, resolves Registry's still-inactive signed candidate,
and evaluates the operator-bound `decisions[target_id]` snapshot. Its first source
derivation is `test-result` version `1`, field `tests.passed`: exact canonical source
bytes must bind the request's artifact digest and contain a boolean. Gate derives
the value itself, checks content hashes/lineage and refuses unsupported derivations.
Current authority is checked again before recording. Candidates remain inactive;
the separate operator binding permits only decision evaluation.

The journal commits exact request, receipt and sequenced event bytes before Server
recording. Gate returns a result only after matching event and archive acknowledgements.
An unavailable recording dependency yields 503, not permission. One process owns the
journal and serializes operations; a pending intent blocks new evaluations. An exact
resubmission can finish recording; lookup never repairs or submits. Identity refusal
is 403, malformed input 400 and changed operation content 409. Recorded semantic
refusals are 200 with the original request binding and `reasons`, without an outcome.

Recovery checks current authority and the original origin, actor and kind, so callers
may refresh expiring assertions while retaining the original request bytes. A missing
local entry is recovered from Server's archive before evaluation. No endpoint issues
an execution grant or dispatches a target action. Read-only replay does not grant new
authority. Journal custody must not be shared by multiple writers or restored while
another process uses it.

[Harness service tests](https://github.com/iokaio/munarium-harness/blob/main/docs/service-profile.md)
exercise both Server stores, including a lost acknowledgement after Server commits
followed by Gate restart with an unavailable evaluator. Warden verifier/transport
exports retain source locks and licenses; re-export through Warden's scripts.
Formal acceptance, independent review and production qualification remain pending.
