#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native Linux evaluator and independently observed cgroup negative controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from check_opa import capabilities
import opa_worker_linux as worker

PIN = "sha256:668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"


def native_request(engine, caps, code, value):
    return dict(executable=str(engine), digest=PIN, capabilities=caps, policy=code, input=value)


def invoke(request, env=None):
    return subprocess.run([sys.executable, str(Path(worker.__file__))], input=json.dumps(request).encode(),
                          capture_output=True, timeout=5, env=env)


def resource_control(root, name, code, counter, expected_failure):
    group = root / ("control-" + uuid.uuid4().hex)
    group.mkdir()
    try:
        for key, value in worker.LIMITS.items():
            (group / key).write_text(value)
        worker.verify_limits(group)

        def enter():
            (group / "cgroup.procs").write_text(str(os.getpid()))

        result = subprocess.run([sys.executable, "-c", code], preexec_fn=enter,
                                capture_output=True, timeout=5)
        events = dict(line.split() for line in (group / counter).read_text().splitlines())
        assert bool(result.returncode) == expected_failure, name
        assert int(events["oom_kill" if counter == "memory.events" else "max"]) > 0, name
        print(f"{name}: passed (kernel counter observed)")
    finally:
        worker.cleanup(group)
    assert not group.exists(), "control group leaked"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opa", type=Path, required=True)
    args = parser.parse_args()
    engine = args.opa.resolve(strict=True)
    with engine.open("rb") as source:
        assert "sha256:" + hashlib.file_digest(source, "sha256").hexdigest() == PIN
    root = worker.delegation()
    initial = set(root.iterdir())
    caps = capabilities(engine)
    policy = ('package munarium\nimport rego.v1\n'
              'decision := {"allow": input.amount + 0 <= 10, "forbid": false, "rules": ["permit"], "predicates": {}, "diagnostics": []}')
    cases = [("allow", policy, {"amount": 1}, True), ("deny", policy, {"amount": 20}, True),
             ("missing", policy, {}, False), ("type-error", policy, {"amount": "one"}, False),
             ("network", 'package munarium\nimport rego.v1\ndecision := http.send({"method":"GET","url":"https://example.test"})', {}, False),
             ("clock", 'package munarium\nimport rego.v1\ndecision := time.now_ns()', {}, False)]
    for name, code, value, success in cases:
        result = invoke(native_request(engine, caps, code, value))
        assert (result.returncode == 0) == success, f"{name}: exit={result.returncode}, {result.stderr.decode()}"
        if success:
            decision = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
            assert decision["allow"] == (name == "allow"), name
        else:
            assert not result.stdout, name
        assert set(root.iterdir()) == initial, "invocation group leaked"
        print(f"{name}: passed")
    work = ('package munarium\nimport rego.v1\n'
            'decision := count({[a,b,c,d,e] | a := input.items[_]; b := input.items[_]; c := input.items[_]; d := input.items[_]; e := input.items[_]})')
    for size, success in [(1, True), (200, False)]:
        result = invoke(native_request(engine, caps, work, {"items": list(range(size))}))
        assert (result.returncode == 0) == success
        assert set(root.iterdir()) == initial
        print(f"resource-control-{size}: passed")
    substituted = native_request(engine, caps, policy, {"amount": 1})
    substituted["digest"] = "sha256:" + "0" * 64
    result = invoke(substituted)
    assert result.returncode != 0 and not result.stdout
    env = os.environ.copy()
    env.pop("MUNARIUM_OPA_CGROUP_ROOT", None)
    result = invoke(native_request(engine, caps, policy, {"amount": 1}), env)
    assert result.returncode != 0 and not result.stdout
    print("substitution/missing-delegation: passed")
    resource_control(root, "resident-memory", 'a=bytearray(128*1024*1024)', "memory.events", True)
    resource_control(root, "process-count", 'import subprocess\np=[]\ntry:\n for _ in range(32): p.append(subprocess.Popen(["/bin/sleep","30"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))\nexcept OSError:\n pass', "pids.events", False)
    assert set(root.iterdir()) == initial, "descendants or groups leaked"


if __name__ == "__main__":
    main()
