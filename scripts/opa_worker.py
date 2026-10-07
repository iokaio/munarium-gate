#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One bounded OPA invocation. Request input is from the privileged Gate adapter."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def memory_boundary():
    """Windows inherited Job Object; unsupported hosts fail closed, never unbounded."""
    if os.name != "nt":
        raise RuntimeError("this worker requires the Windows Job Object profile")
    from ctypes import wintypes as w
    size = ctypes.c_size_t
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", w.DWORD), ("minimum_working_set", size), ("maximum_working_set", size),
                    ("active_process_limit", w.DWORD), ("affinity", size),
                    ("priority_class", w.DWORD), ("scheduling_class", w.DWORD)]
    class Io(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("read_operations", "write_operations", "other_operations", "read_bytes", "write_bytes", "other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", Io), ("process_memory", size), ("job_memory", size),
                    ("peak_process_memory", size), ("peak_job_memory", size)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.SetInformationJobObject.restype = w.BOOL
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    kernel.AssignProcessToJobObject.restype = w.BOOL
    job = kernel.CreateJobObjectW(None, None)
    limit = Extended()
    limit.basic.flags = 0x100 | 0x2000  # PROCESS_MEMORY, KILL_ON_JOB_CLOSE
    limit.process_memory = 64 * 1024 * 1024
    if (not job or not kernel.SetInformationJobObject(job, 9, ctypes.byref(limit), ctypes.sizeof(limit))
            or not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess())):
        raise RuntimeError("memory boundary unavailable")
    # Keep this handle until process exit. OPA inherits job membership, not the handle.
    return job


def main():
    raw = sys.stdin.buffer.read(262145)
    if len(raw) > 262144:
        raise ValueError("input limit")
    request = json.loads(raw)
    executable = Path(request["executable"]).resolve(strict=True)
    if "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest() != request["digest"]:
        raise ValueError("engine pin")
    capabilities = request["capabilities"]
    # No ambient I/O, time, randomness, DNS or runtime environment builtins.
    allowed = {"eq", "neq", "equal", "lt", "lte", "gt", "gte", "plus", "minus", "mul", "div", "rem",
               "count", "is_boolean", "is_number", "is_string", "is_array", "is_object", "is_set", "is_null",
               "internal.member_2", "internal.member_3", "object.get", "array.concat", "concat"}
    if (set(capabilities) - {"builtins", "future_keywords", "features", "allow_net"}
            or capabilities.get("allow_net", []) != []
            or any(b["name"] not in allowed for b in capabilities["builtins"])):
        raise ValueError("capabilities")
    job = memory_boundary()
    with tempfile.TemporaryDirectory(prefix="munarium-gate-opa-") as directory:
        root = Path(directory)
        (root / "policy.rego").write_text(request["policy"], encoding="utf-8")
        (root / "input.json").write_text(json.dumps(request["input"], ensure_ascii=False), encoding="utf-8")
        (root / "capabilities.json").write_text(json.dumps(capabilities), encoding="utf-8")
        command = [str(executable), "eval", "--strict", "--strict-builtin-errors", "--fail", "--timeout", "100ms",
                   "--format", "json", "--capabilities", str(root / "capabilities.json"),
                   "--data", str(root / "policy.rego"), "--input", str(root / "input.json"), "data.munarium.decision"]
        result = subprocess.run(command, capture_output=True, timeout=0.1, check=False,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                env={k: v for k, v in os.environ.items()
                                     if k.upper() in {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP"}})
        if result.returncode or result.stderr or len(result.stdout) > 65536:
            raise ValueError("evaluation refused")
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
    return bool(job) is False


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Raw worker/provider diagnostics can contain submitted inputs.
        sys.exit(1)
