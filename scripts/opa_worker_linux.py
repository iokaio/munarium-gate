#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded Linux OPA worker. Delegation is operator configuration, never request data."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

MEMORY = 64 * 1024 * 1024
INPUT = 262144
OUTPUT = 65536
LIMITS = {"memory.max": str(MEMORY), "memory.swap.max": "0",
          "memory.oom.group": "1", "pids.max": "16", "cpu.max": "100000 100000"}
ALLOW = {"eq", "neq", "equal", "lt", "lte", "gt", "gte", "plus", "minus", "mul", "div", "rem",
         "count", "is_boolean", "is_number", "is_string", "is_array", "is_object", "is_set", "is_null",
         "internal.member_2", "internal.member_3", "object.get", "array.concat", "concat"}


def read_request():
    raw = sys.stdin.buffer.read(INPUT + 1)
    if len(raw) > INPUT:
        raise ValueError("input limit")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"executable", "digest", "policy", "input", "capabilities"}:
        raise ValueError("request")
    return raw, value


def delegation():
    if sys.platform != "linux":
        raise RuntimeError("Linux cgroup v2 required")
    root = Path(os.environ["MUNARIUM_OPA_CGROUP_ROOT"]).resolve(strict=True)
    mount = Path("/sys/fs/cgroup").resolve(strict=True)
    if root == mount or not root.is_relative_to(mount):
        raise ValueError("dedicated delegation required")
    # A directory resembling sysfs cannot substitute for kernel enforcement.
    stat = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.statfs(os.fsencode(root), stat) or ctypes.c_long.from_buffer(stat).value != 0x63677270:
        raise RuntimeError("cgroup filesystem required")
    if not {"memory", "pids", "cpu"}.issubset(set((root / "cgroup.subtree_control").read_text().split())):
        raise RuntimeError("controllers unavailable")
    return root


def verify_limits(group):
    for name, expected in LIMITS.items():
        if (group / name).read_text().strip() != expected:
            raise RuntimeError("resource boundary unavailable")
    if not (group / "cgroup.kill").is_file():
        raise RuntimeError("whole-group cleanup unavailable")


def validate_capabilities(caps):
    if (not isinstance(caps, dict)
            or set(caps) - {"builtins", "future_keywords", "features", "allow_net"}
            or caps.get("allow_net", []) != []
            or not isinstance(caps.get("builtins"), list)
            or any(not isinstance(b, dict) or b.get("name") not in ALLOW for b in caps["builtins"])):
        raise ValueError("capabilities")


def evaluate(group, request):
    verify_limits(group)
    if str(os.getpid()) not in (group / "cgroup.procs").read_text().split():
        raise RuntimeError("worker outside boundary")
    caps = request["capabilities"]
    validate_capabilities(caps)
    if not isinstance(request["policy"], str):
        raise ValueError("policy")
    with tempfile.TemporaryDirectory(prefix="munarium-gate-opa-") as directory:
        root = Path(directory)
        (root / "policy.rego").write_text(request["policy"], encoding="utf-8")
        (root / "input.json").write_text(json.dumps(request["input"], ensure_ascii=False), encoding="utf-8")
        (root / "capabilities.json").write_text(json.dumps(caps), encoding="utf-8")
        command = [request["executable"], "eval", "--strict", "--strict-builtin-errors", "--fail",
                   "--timeout", "100ms", "--format", "json", "--capabilities", str(root / "capabilities.json"),
                   "--data", str(root / "policy.rego"), "--input", str(root / "input.json"), "data.munarium.decision"]
        result = subprocess.run(command, capture_output=True, timeout=0.1, check=False,
                                env={"GOMAXPROCS": "1", "GOMEMLIMIT": "32MiB", "TMPDIR": directory})
        if result.returncode or result.stderr or len(result.stdout) > OUTPUT:
            raise ValueError("evaluation refused")
        return result.stdout


def cleanup(group):
    # A setup failure may precede controller creation. No process may have been
    # launched without verify_limits; still refuse if the kernel reports members.
    if (group / "cgroup.kill").is_file():
        (group / "cgroup.kill").write_text("1")
    deadline = time.monotonic() + 1
    while "populated 1" in (group / "cgroup.events").read_text():
        if time.monotonic() >= deadline:
            raise RuntimeError("descendant cleanup failed")
        time.sleep(0.005)
    group.rmdir()


def supervise(raw, request):
    root = delegation()
    executable = Path(request["executable"]).resolve(strict=True)
    with executable.open("rb") as source:
        digest = "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()
    if digest != request["digest"]:
        raise ValueError("engine pin")
    # Child receives the exact resolved path checked by the trusted supervisor.
    request["executable"] = str(executable)
    raw = json.dumps(request).encode()
    group = root / ("eval-" + uuid.uuid4().hex)
    group.mkdir()
    output = None
    try:
        for name, value in LIMITS.items():
            (group / name).write_text(value)
        verify_limits(group)

        def enter():
            (group / "cgroup.procs").write_text(str(os.getpid()))

        # Output is a bounded file, not a pipe whose reader might retain unlimited
        # output. The bounded child and native output checks supplement this cap.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", str(group)],
                                       stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                       preexec_fn=enter, env={"PATH": os.defpath})
            try:
                process.communicate(raw, timeout=2)
            except BaseException:
                (group / "cgroup.kill").write_text("1")
                process.wait(timeout=1)
                raise
            stdout.seek(0)
            stderr.seek(0)
            output = stdout.read(OUTPUT + 1)
            if process.returncode or stderr.read(1) or len(output) > OUTPUT:
                raise ValueError("worker refused")
            events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
            if int(events.get("oom", 0)) or int(events.get("oom_kill", 0)):
                raise ValueError("memory limit")
    finally:
        cleanup(group)
    # Permission is never emitted before successful whole-group cleanup.
    return output


def main():
    raw, request = read_request()
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        result = evaluate(Path(sys.argv[2]), request)
    elif len(sys.argv) == 1:
        result = supervise(raw, request)
    else:
        raise ValueError("worker invocation")
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
