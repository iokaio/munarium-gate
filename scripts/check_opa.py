#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run bounded native OPA positive and negative controls using public synthetic inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN = "sha256:25406f7c6e147d687fd7fd546f835bafa160a6242c605ee94a23ba6cd7bccdcd"
ALLOW = {"eq", "neq", "equal", "lt", "lte", "gt", "gte", "plus", "minus", "mul", "div", "rem",
         "count", "is_boolean", "is_number", "is_string", "is_array", "is_object", "is_set", "is_null",
         "internal.member_2", "internal.member_3", "object.get", "array.concat", "concat"}


def capabilities(executable):
    raw = subprocess.check_output([str(executable), "capabilities", "--current"], timeout=5)
    value = json.loads(raw)
    value["builtins"] = [b for b in value["builtins"] if b["name"] in ALLOW]
    value["allow_net"] = []
    value.pop("wasm_abi_versions", None)
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--opa", type=Path, required=True)
    args = p.parse_args()
    engine = args.opa.resolve(strict=True)
    if "sha256:" + hashlib.sha256(engine.read_bytes()).hexdigest() != PIN:
        raise ValueError("engine pin")
    caps = capabilities(engine)
    worker = Path(__file__).with_name("opa_worker.py")
    policy = '''package munarium
import rego.v1
decision := {"allow": input.amount + 0 <= 10, "forbid": false, "rules": ["permit"], "predicates": {}, "diagnostics": []}
'''
    cases = [("allow", policy, {"amount": 1}, True),
             ("deny", policy, {"amount": 20}, True),
             ("missing", policy, {}, False),
             ("type-error", policy, {"amount": "one"}, False),
             ("network", 'package munarium\nimport rego.v1\ndecision := http.send({"method":"GET","url":"https://example.test"})', {}, False),
             ("clock", 'package munarium\nimport rego.v1\ndecision := time.now_ns()', {}, False)]
    for name, code, value, expected in cases:
        request = dict(executable=str(engine), digest=PIN, capabilities=caps, policy=code, input=value)
        result = subprocess.run([sys.executable, str(worker)], input=json.dumps(request).encode(), capture_output=True, timeout=5)
        if (result.returncode == 0) != expected:
            raise AssertionError(f"{name}: expected success={expected}, exit={result.returncode}")
        if expected:
            decision = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
            assert decision["allow"] == (name == "allow")
        print(f"{name}: passed (exit {result.returncode})")
    # Same policy with a small positive input and an excessive cross product.
    # Successful small evaluation rules out a syntax/unsupported-builtin false positive.
    code = 'package munarium\nimport rego.v1\ndecision := count({[a,b,c,d,e] | a := input.items[_]; b := input.items[_]; c := input.items[_]; d := input.items[_]; e := input.items[_]})'
    for size, success in [(1, True), (200, False)]:
        request = dict(executable=str(engine), digest=PIN, capabilities=caps, policy=code, input={"items": list(range(size))})
        result = subprocess.run([sys.executable, str(worker)], input=json.dumps(request).encode(), capture_output=True, timeout=5)
        assert (result.returncode == 0) == success
        print(f"resource-control-{size}: passed (exit {result.returncode})")
    probe = 'import opa_worker; handle=opa_worker.memory_boundary(); allocation=bytearray(128*1024*1024)'
    result = subprocess.run([sys.executable, "-c", probe], cwd=worker.parent, capture_output=True, timeout=5)
    assert result.returncode != 0 and b"MemoryError" in result.stderr
    print("memory-allocation-negative-control: passed")


if __name__ == "__main__":
    main()
