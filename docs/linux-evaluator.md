# Experimental Linux evaluator

The [Linux worker](../scripts/opa_worker_linux.py) implements LINUX-01 under hub
[ADR 0015](https://github.com/iokaio/munarium-platform/blob/349059e16c38a66adc725c87ca6a9059260c32c9/docs/decisions/0015-stage2-linux-qualification.md).
Select it in the existing operator-owned evaluator configuration and pin its actual
file digest. Existing Windows worker bytes and candidate contracts are unchanged.

The native engine is OPA 1.21.1 `opa_linux_amd64_static`, SHA-256
`668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031`, from the
[official release](https://github.com/open-policy-agent/opa/releases/tag/v1.21.1).
This pin does not establish reproducible builds or production qualification.

An administrator delegates a dedicated cgroup v2 subtree with `cpu`, `memory` and
`pids` enabled. Set `MUNARIUM_OPA_CGROUP_ROOT` in the trusted Gate environment to
that directory under `/sys/fs/cgroup`. Gate does not alter global controllers or
create delegation. An absent, simulated, unsupported or unwritable boundary refuses.
The supervisor must already reside in a child of that delegated subtree, so moving
its children requires only delegated permissions. An administrator establishes
that service placement; the evaluator does not move itself from an unrelated host
cgroup. CI places the supervisor first and runs evaluation as the ordinary runner.

Each invocation creates a fresh kernel cgroup and places the Python child inside
before executing native OPA. Limits are aggregate 64 MiB resident memory, zero
swap, 16 tasks and one CPU of quota. The trusted supervisor stays outside that
invocation group. OPA gets a pure capability allowlist, strict errors and a 100 ms
deadline, with a matching subprocess timeout. Input is at most 256 KiB and output
64 KiB. The supervisor allows two seconds for child startup/input/evaluation and
refuses errors, output overflow, diagnostics or OOM events. It kills descendants
and removes only the invocation group before returning a successful native result.

These are resource controls for pinned code, not OS isolation against a hostile
executable or host administrator. Dynamic action integration, actual agent network/
mount isolation and restore reopening remain separate work. A native policy permit
does not create an execution grant or send permission.

## Validation

With the pinned executable and delegated subtree already available:

```console
python3 scripts/test_linux_worker.py -v
python3 scripts/check_opa_linux.py --opa PATH_TO_OPA
OPA_LINUX_EXECUTABLE=PATH_TO_OPA cargo test --offline --locked --test native_opa -- --ignored
```

Portable tests prove malformed/configurable-boundary refusal, missing delegation
and capability filtering. They do not prove kernel enforcement. Native controls
require successful allow/deny and small-work evaluation before resource failures,
reject missing/type-invalid inputs, forbidden I/O/time, binary substitution and
absent delegation, and verify group cleanup. Independent memory/process probes
inspect actual kernel OOM/process-limit counters. The Rust test exercises the real
worker through the existing adapter and rejects substituted worker pins.

The additive Linux job in the [workflow](../.github/workflows/rust.yml) explicitly
selects native tests, creates a dedicated disposable delegation and cleans only
its own group. Windows native controls and ordinary Rust/PostgreSQL/service suites
remain enabled. Local unavailable native coverage is reported, not marked passed.
