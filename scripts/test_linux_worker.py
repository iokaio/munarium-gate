#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Portable Linux-worker refusal controls; native cgroup evidence is separate."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import opa_worker_linux as worker


class WorkerControls(unittest.TestCase):
    def test_pure_capabilities(self):
        caps = {"builtins": [{"name": "plus"}], "allow_net": []}
        worker.validate_capabilities(caps)
        for change in ({"allow_net": ["example.test"]}, {"builtins": [{"name": "http.send"}]},
                       {"builtins": [{"name": "time.now_ns"}]}, {"unknown": True},
                       {"builtins": ["plus"]}, {"builtins": None}):
            invalid = copy.deepcopy(caps)
            invalid.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                worker.validate_capabilities(invalid)

    def test_absent_delegation_has_no_output(self):
        env = os.environ.copy()
        env.pop("MUNARIUM_OPA_CGROUP_ROOT", None)
        request = b'{"executable":"absent","digest":"absent","policy":"","input":{},"capabilities":{}}'
        result = subprocess.run([sys.executable, str(Path(worker.__file__))], input=request,
                                env=env, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_caller_cannot_configure_boundary(self):
        request = b'{"executable":"absent","digest":"absent","policy":"","input":{},"capabilities":{},"memory":999999999}'
        result = subprocess.run([sys.executable, str(Path(worker.__file__))], input=request,
                                capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    @unittest.skipUnless(sys.platform == "linux", "kernel path checks require Linux")
    def test_regular_directory_cannot_supply_delegation(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("MUNARIUM_OPA_CGROUP_ROOT")
            try:
                os.environ["MUNARIUM_OPA_CGROUP_ROOT"] = directory
                with self.assertRaises(ValueError):
                    worker.delegation()
            finally:
                if previous is None:
                    os.environ.pop("MUNARIUM_OPA_CGROUP_ROOT", None)
                else:
                    os.environ["MUNARIUM_OPA_CGROUP_ROOT"] = previous


if __name__ == "__main__":
    unittest.main()
