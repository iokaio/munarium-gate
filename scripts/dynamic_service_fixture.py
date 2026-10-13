# SPDX-License-Identifier: Apache-2.0
"""Synthetic authenticated owner inputs for the actual Gate/native OPA service test."""
import copy
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from check_opa import capabilities
from check_opa_linux import PIN


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(domain, value):
    return "sha256:" + hashlib.sha256((domain + "\0" + encoded(value)).encode()).hexdigest()


class Dynamic:
    def __init__(self, root, scope, vectors, transition):
        self.root, self.scope = root, scope
        executable = Path(os.environ["OPA_LINUX_EXECUTABLE"]).resolve(strict=True)
        worker = Path(__file__).with_name("opa_worker_linux.py").resolve(strict=True)
        self.evaluator = dict(python=sys.executable, worker=str(worker), executable=str(executable),
            worker_digest="sha256:"+hashlib.sha256(worker.read_bytes()).hexdigest(), executable_digest=PIN,
            version="1.21.1", capabilities=capabilities(executable))
        template = copy.deepcopy(vectors["records"]["request"])

        def scoped(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "scope": value[key] = scope
                    else: scoped(child)
            elif isinstance(value, list):
                for child in value: scoped(child)

        scoped(template)
        now = int(time.time())
        template["operation"]["id"] = "native-dynamic"
        template["attempt"]["id"] = "native-attempt"
        template["context"].update(valid_from=now-10, expires_at=now+600)
        schema = dict(type="object", properties=dict(artifact_digest=dict(type="string"), destination=dict(type="string")),
            required=["artifact_digest", "destination"], additionalProperties=False)
        self.manifest = dict(schema_version=2, profile="registry-manifest-v2", tenant=scope["tenant"],
            operation_id="release.publish_approved_artifact", environment="disposable", target_id=template["intent"]["target"]["id"],
            credential_audience=template["intent"]["target"]["id"], base_consequence="C2", effect="external-effect",
            idempotency="operation-key", compensation="none", modifiers=[], required_obligations=["distinct-approval"],
            parameter_schema_digest=digest("munarium:capability-schema:v1", schema))
        self.policy = dict(profile="stage2-release-evaluation-v1", engine="opa", engine_version="1.21.1", engine_digest=PIN,
            worker_digest=self.evaluator["worker_digest"], capabilities_digest=digest("munarium:opa-capabilities:v1", self.evaluator["capabilities"]),
            parameter_schema=schema, rule_obligations=dict(permit="distinct-approval"),
            code='package munarium\nimport rego.v1\ndecision := {"allow": input.evidence.tests_passed, "forbid": false, "rules": ["permit"], "predicates": {}, "diagnostics": []}')
        template["intent"]["parameter_schema_digest"] = self.manifest["parameter_schema_digest"]
        context = template["context"]
        context["manifest_digest"] = digest("munarium:manifest:v2", self.manifest)
        context["policy_digest"] = digest("munarium:decision-policy:v1", self.policy)
        context["evaluator_profile_digest"] = digest("munarium:stage2:evaluator-profile:v1", dict(engine="opa", version="1.21.1", binary=PIN,
            worker=self.evaluator["worker_digest"], capabilities=self.policy["capabilities_digest"]))
        source = encoded({"artifact_digest":template["intent"]["parameters"]["artifact_digest"], "tests.passed":True})
        context["evidence"][0].update(content_digest="sha256:"+hashlib.sha256(source.encode()).hexdigest(), derivation="test-result",
            derivation_version=1, field="tests.passed", observed_at=now-10, expires_at=now+600)
        template["intent_digest"] = digest("munarium:stage2:intent:v1", template["intent"])
        template["context_digest"] = digest("munarium:stage2:context:v1", context)
        self.template = template
        transition["artifacts"] = [dict(kind="manifest", digest=context["manifest_digest"]), dict(kind="policy", digest=context["policy_digest"])]
        transition["artifact_set_digest"] = digest("munarium:stage2:artifact-set:v1", {"artifacts":transition["artifacts"]})
        self.bindings = {"execution:gate":dict(scope=scope, council="council", warden="warden", connector="connector", readers=["reader"],
            stream="dynamic-test", generation=1, recovery=1, requests={"native-dynamic":dict(proposer="agent", request=template,
                requester_chain=[template["intent"]["actor"]], evaluation=dict(evidence_source=source))}),
            "stage2:registry":dict(artifacts=[dict(a, profile="stage2-single-cell-v1", retired=False,
                **({"policy":self.policy} if a["kind"] == "policy" else {})) for a in transition["artifacts"]])}
        denied = copy.deepcopy(self.bindings["execution:gate"]["requests"]["native-dynamic"])
        denied["request"]["operation"]["id"] = "native-denied"
        denied["request"]["attempt"]["id"] = "denied-attempt"
        denied_source = encoded({"artifact_digest":template["intent"]["parameters"]["artifact_digest"], "tests.passed":False})
        denied["evaluation"]["evidence_source"] = denied_source
        denied["request"]["context"]["evidence"][0]["source"]["id"] = "denied-test-result"
        denied["request"]["context"]["evidence"][0]["content_digest"] = "sha256:"+hashlib.sha256(denied_source.encode()).hexdigest()
        denied["request"]["context_digest"] = digest("munarium:stage2:context:v1", denied["request"]["context"])
        self.bindings["execution:gate"]["requests"]["native-denied"] = denied
        self.openssl = shutil.which("openssl") or "C:/Program Files/Git/usr/bin/openssl.exe"
        self.issuer = root / "dynamic-issuer.key"
        subprocess.run([self.openssl, "genpkey", "-algorithm", "ED25519", "-out", str(self.issuer)], check=True, capture_output=True)
        public = subprocess.run([self.openssl, "pkey", "-in", str(self.issuer), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
        assert len(public) == 44, "Ed25519 public-key encoding"
        restriction = dict(digest=context["policy_digest"], nbf=now-10, exp=now+600, scopes=["read"], resources=["registry:"+scope["tenant"]])
        self.bindings["identity:registry"] = dict(keys={"dynamic":dict(public_key=self.b64(public[-32:]), issuer="warden", decision=True)},
            peers={"gate":dict(task=restriction, policy=restriction, maximum_depth=0)}, registrations=[])
        (root/"provider-token").write_text("synthetic-provider-token")
        self.archived = {}
        self.wrong_archive = False
        self.issued = 0

    @staticmethod
    def b64(raw):
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def assertion(self):
        now = int(time.time())
        header = dict(alg="Ed25519", kid="dynamic", typ="munarium-principal+jws")
        payload = dict(schema_version=1, deployment=self.scope["deployment"], tenant=self.scope["tenant"], issuer="warden",
            audience="registry", origin="gate", actor="gate", origin_kind="service", service="gate", purpose="decision",
            scopes=["read"], resources=["registry:"+self.scope["tenant"]], iat=now-3, nbf=now-3, exp=now+57, parent_digest=None, bootstrap=None)
        message = (self.b64(encoded(header).encode()) + "." + self.b64(encoded(payload).encode())).encode()
        with tempfile.TemporaryDirectory(dir=self.root, prefix="assertion-") as directory:
            path = Path(directory) / "input"
            path.write_bytes(message)
            signature = subprocess.run([self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.issuer), "-in", str(path)], check=True, capture_output=True).stdout
        return message.decode() + "." + self.b64(signature)

    def configure(self, config):
        config.update(evaluator=self.evaluator, provider_token_file=str(self.root/"provider-token"),
                      execution=dict(target_endpoint="https://127.0.0.1:1"))

    def answer(self, handler, action):
        if handler.path.endswith("/v1/identity"):
            self.issued += 1
            handler.answer(dict(chain=[self.assertion()], usable_at=int(time.time())-1)); return True
        if handler.path.endswith("/v1/candidates"):
            handler.answer(dict(status="candidate", active=False, manifest=self.manifest,
                manifest_digest=self.template["context"]["manifest_digest"])); return True
        if "/records" in handler.path:
            assert action["operation"] == "action-archive"
            value = json.loads(action["record"])
            kind = value["type"]
            key = (kind, value["operation"]["id"])
            prior = self.archived.setdefault(key, action["record"])
            assert prior == action["record"], "immutable archive retry"
            handler.answer(dict(record_type=kind, digest=("sha256:"+"0"*64 if self.wrong_archive else
                digest("munarium:stage2:"+kind+":v1", value)), ledger_position=len(self.archived))); return True
        return False

    def exercise(self, test, call, refused, restart):
        proposal = dict(operation="propose", operation_id="native-dynamic", attempt_id="native-attempt",
                        parameters=self.template["intent"]["parameters"])
        refused(proposal, "reader")
        refused(proposal, "agent", "foreign")
        wrong = copy.deepcopy(proposal)
        wrong["parameters"]["artifact_digest"] = "sha256:"+"0"*64
        refused(wrong, "agent")
        self.wrong_archive = True
        refused(proposal, "agent")
        self.wrong_archive = False
        first = call(proposal, "agent")
        test.assertEqual(first["decision"]["outcome"], "approval-required")
        test.assertEqual(len(first["decision"]["obligations"]), 4)
        test.assertEqual({key[0] for key in self.archived}, {"action-request", "action-decision"})
        issued = self.issued
        test.assertEqual(call(proposal, "agent"), first)
        test.assertEqual(self.issued, issued, "qualified identity retry must not issue another root")
        denied = dict(proposal, operation_id="native-denied", attempt_id="denied-attempt")
        verdict = call(denied, "agent")
        test.assertEqual(verdict["decision"]["outcome"], "denied")
        test.assertEqual(verdict["decision"]["obligations"], [])
        restart()
        test.assertEqual(call(proposal, "agent"), first)
        test.assertGreater(self.issued, issued, "process restart must discard identity retention")
        test.assertEqual(call(dict(operation="source", operation_id="native-dynamic", attempt_id="native-attempt"), "reader"), first)
        refused(wrong, "agent")
        refused(dict(operation="prepare", operation_id="native-dynamic", attempt_id="native-attempt"), "agent")
        # Current artifact retirement invalidates retained-source admission; no reevaluation can renew it.
        self.bindings["stage2:registry"]["artifacts"][0]["retired"] = True
        refused(proposal, "agent")
