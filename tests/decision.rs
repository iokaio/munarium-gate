// SPDX-License-Identifier: Apache-2.0
use munarium_gate::decision::*;
use serde_json::{Value, json};

#[test]
fn receiver_preserves_unchanged_canonical_vectors_and_vendor_pins() {
    use sha2::{Digest, Sha256};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/stage1");
    let lock: Value =
        serde_json::from_slice(&std::fs::read(root.join("vendor-lock.json")).unwrap()).unwrap();
    for (name, pin) in lock["files"].as_object().unwrap() {
        let raw = std::fs::read_to_string(root.join(name))
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(
            format!("{:x}", Sha256::digest(raw.as_bytes())),
            pin["sha256"]
        );
    }
    let vectors: Value = serde_json::from_str(include_str!(
        "../contracts/stage1/decision-json-v1-vectors.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        if case["result"] == "reject" {
            assert!(
                parse(case["input"].as_str().unwrap().as_bytes()).is_err(),
                "{}",
                case["id"]
            );
        } else {
            let raw = case["canonical"].as_str().unwrap().as_bytes();
            parse(raw).unwrap();
            assert_eq!(digest("munarium:decision-request:v1", raw), case["digest"]);
        }
    }
}

fn pin(v: &Value, domain: &str) -> String {
    digest(domain, &serde_json::to_vec(v).unwrap())
}
struct Worker {
    output: Value,
    calls: usize,
}
impl Engine for Worker {
    fn name(&self) -> &'static str {
        "opa"
    }
    fn version(&self) -> &str {
        "1.21.1"
    }
    fn digest(&self) -> &str {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
    fn evaluate(&mut self, _: &Value, _: &Value) -> Result<Value, Error> {
        self.calls += 1;
        Ok(self.output.clone())
    }
}
struct Adapters {
    snapshot: Snapshot,
    request: Value,
    records: Vec<Value>,
    missing: bool,
    recording: bool,
}
impl Host for Adapters {
    fn principal(&mut self, _: &[String]) -> Result<Principal, Error> {
        Ok(Principal {
            origin: "fixture-agent".into(),
            actor: "fixture-agent".into(),
            origin_kind: "agent".into(),
            tenant: "alpha".into(),
            digest: self.request["principal_digest"].as_str().unwrap().into(),
            scopes: vec!["evaluate".into()],
            resources: vec!["fixture-target".into()],
        })
    }
    fn snapshot(&mut self, _: &str, _: &Value) -> Result<Snapshot, Error> {
        if self.missing {
            Err(Error::Manifest)
        } else {
            Ok(self.snapshot.clone())
        }
    }
    fn record(&mut self, _: &Value, d: &Value, _: &[u8]) -> Result<(), Error> {
        if !self.recording {
            return Err(Error::Recording);
        }
        self.records.push(d.clone());
        Ok(())
    }
}
fn fixture() -> (Value, Adapters, Worker) {
    let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"key":{"type":"string","minLength":1,"maxLength":64}},"required":["key"],"additionalProperties":false});
    let manifest = json!({"schema_version":2,"profile":"registry-manifest-v2","tenant":"alpha","target_id":"fixture-target","environment":"test","capability_id":"read-item","parameter_schema_digest":pin(&schema,"munarium:capability-schema:v1"),"base_consequence":"C0","modifiers":[],"required_obligations":[],"required_inputs":[]});
    let engine = Worker {
        calls: 0,
        output: json!({"allow":true,"forbid":false,"rules":["permit"],"predicates":{},"diagnostics":[]}),
    };
    let policy = json!({"engine":"opa","version":"1.21.1","engine_digest":engine.digest(),"rules":{"permit":null,"approval":{"kind":"distinct-approval","approver_scope":"council:ratify"}},"inputs":[],"code":"fixture-only"});
    let request = json!({"schema_version":1,"profile":"decision-json-v1","tenant":"alpha","operation_id":"op-1","principal_digest":engine.digest(),"target_id":"fixture-target","environment":"test","capability_id":"read-item","manifest_digest":pin(&manifest,"munarium:manifest:v2"),"policy_digest":pin(&policy,"munarium:decision-policy:v1"),"activation_epoch":1,"mode":"enforce","parameters":{"key":"hello"},"attachments":[]});
    let binding = json!({"available":true,"artifact_digest":engine.digest(),"tenant":"alpha","target_id":"fixture-target","environment":"test","manifest_digest":request["manifest_digest"],"policy_digest":request["policy_digest"],"activation_epoch":1,"mode":"enforce"});
    let host = Adapters {
        snapshot: Snapshot {
            manifest,
            artifact_digest: engine.digest().into(),
            binding,
            policy,
            parameter_schema: schema,
            evidence: vec![],
            attachments: vec![],
        },
        request: request.clone(),
        records: vec![],
        missing: false,
        recording: true,
    };
    (request, host, engine)
}
fn run(r: &Value, h: &mut Adapters, e: &mut Worker) -> Result<Receipt, Error> {
    decide(&serde_json::to_vec(r).unwrap(), &[], h, e)
}

#[test]
fn ref01_replays_exact_decision_without_recording_or_dispatch() {
    let (r, mut h, mut e) = fixture();
    let receipt = run(&r, &mut h, &mut e).unwrap();
    assert_eq!(receipt.decision()["outcome"], "decision-only-allow");
    assert_eq!(receipt.replay(&mut e).unwrap(), *receipt.decision());
    assert_eq!(h.records.len(), 1);
    let raw = receipt.export().unwrap();
    let restored = Receipt::restore(&raw, &digest("munarium:decision-replay:v1", &raw)).unwrap();
    assert_eq!(restored.replay(&mut e).unwrap(), *receipt.decision());
    let mut changed = raw.clone();
    changed[0] = b'[';
    assert!(Receipt::restore(&changed, &digest("munarium:decision-replay:v1", &raw)).is_err());
    h.snapshot.binding["mode"] = json!("observe");
    assert_eq!(receipt.replay(&mut e).unwrap(), *receipt.decision());
}
#[test]
fn manifests_activation_parameters_and_tenants_refuse_before_engine() {
    for change in 0..9 {
        let (mut r, mut h, mut e) = fixture();
        match change {
            0 => h.missing = true,
            1 => h.snapshot.binding["available"] = json!(false),
            2 => h.snapshot.binding["activation_epoch"] = json!(2),
            3 => h.snapshot.binding["artifact_digest"] = json!("substituted"),
            4 => h.snapshot.manifest["profile"] = json!("unknown"),
            5 => r["parameters"] = json!({"unknown":true}),
            6 => r["tenant"] = json!("beta"),
            7 => h.snapshot.policy["code"] = json!("changed"),
            _ => {
                r["attachments"] =
                    json!([{"digest":e.digest(),"media_type":"text/plain","bytes":3}])
            }
        }
        let result = run(&r, &mut h, &mut e);
        if change == 6 {
            assert!(matches!(result, Err(Error::Identity)));
            assert!(h.records.is_empty());
        } else {
            let receipt = result.unwrap();
            assert!(receipt.decision().get("outcome").is_none());
            assert_eq!(h.records.len(), 1);
        }
        assert_eq!(e.calls, 0);
    }
}
#[test]
fn diagnostics_deny_precedence_and_obligations_are_distinct() {
    for change in 0..9 {
        let (r, mut h, mut e) = fixture();
        match change {
            0 => e.output["diagnostics"] = json!(["missing attribute"]),
            1 => e.output["forbid"] = json!(true),
            2 => e.output["rules"] = json!(["permit", "approval"]),
            3 => e.output["rules"] = json!(["unknown"]),
            4 => e.output["allow"] = json!("true"),
            5 => e.output["extra"] = json!(true),
            6 => e.output["rules"] = json!(["permit", "permit"]),
            7 => e.output["rules"] = json!([]),
            _ => e.output["predicates"] = json!({"unknown":true}),
        }
        let receipt = run(&r, &mut h, &mut e).unwrap();
        let d = receipt.decision();
        match change {
            1 => {
                assert_eq!(d["outcome"], "denied");
                assert_eq!(d["obligations"], json!([]));
            }
            2 => {
                assert_eq!(d["outcome"], "approval-required");
                assert_eq!(d["obligations"][0]["request_digest"], d["request_digest"]);
            }
            _ => assert_eq!(d["reasons"], json!(["evaluation-error"])),
        }
    }
}
#[test]
fn required_lineage_is_not_agent_promotable_and_recording_is_required() {
    let (mut r, mut h, mut e) = fixture();
    let spec = json!({"field_path":"tests.passed","source_id":"build-a","derivation_id":"test-receipt","derivation_version":"1","permitted_use":"decision"});
    h.snapshot.policy["inputs"] = json!([spec]);
    r["policy_digest"] = json!(pin(&h.snapshot.policy, "munarium:decision-policy:v1"));
    h.snapshot.binding["policy_digest"] = r["policy_digest"].clone();
    assert_eq!(
        run(&r, &mut h, &mut e).unwrap().decision()["reasons"],
        json!(["lineage-unavailable"])
    );
    assert_eq!(e.calls, 0);
    let examples: Value =
        serde_json::from_str(include_str!("../contracts/stage1/record-vectors.json")).unwrap();
    let mut lineage = examples["examples"]["lineage"].clone();
    lineage["tenant"] = json!("alpha");
    lineage["field_path"] = json!("tests.passed");
    lineage["source_id"] = json!("build-a");
    lineage["derivation_id"] = json!("test-receipt");
    lineage["derivation_version"] = json!("1");
    lineage["policy_digest"] = r["policy_digest"].clone();
    lineage["trust"] = json!("verified");
    lineage["revision"] = json!("1");
    lineage["observed_at"] = json!(1000);
    lineage["evidence_ref"] = json!("receipt-a");
    lineage["verifier_ref"] = json!("test-verifier");
    use sha2::{Digest, Sha256};
    lineage["content_digest"] = json!(format!("sha256:{:x}", Sha256::digest(b"test evidence")));
    h.snapshot.evidence.push(Evidence {
        lineage,
        source: b"test evidence".to_vec(),
        value: json!(true),
    });
    assert_eq!(
        run(&r, &mut h, &mut e).unwrap().decision()["outcome"],
        "decision-only-allow"
    );
    for field in ["trust", "tenant", "derivation_version", "content_digest"] {
        let old = h.snapshot.evidence[0].lineage[field].clone();
        h.snapshot.evidence[0].lineage[field] = json!("untrusted");
        assert_eq!(
            run(&r, &mut h, &mut e).unwrap().decision()["reasons"],
            json!(["lineage-unavailable"])
        );
        h.snapshot.evidence[0].lineage[field] = old;
    }
    h.recording = false;
    assert!(matches!(run(&r, &mut h, &mut e), Err(Error::Recording)));
}

#[test]
fn manifest_obligations_survive_permit_and_modifiers_can_only_raise() {
    let (mut r, mut h, mut e) = fixture();
    let predicate = e.digest().to_owned();
    h.snapshot.manifest["base_consequence"] = json!("C1");
    h.snapshot.manifest["modifiers"] = json!([{"predicate_digest":predicate,"raise_to":"C3"}]);
    h.snapshot.manifest["required_obligations"] = json!(["distinct-approval"]);
    h.snapshot.policy["manifest_approver_scope"] = json!("council:ratify");
    r["manifest_digest"] = json!(pin(&h.snapshot.manifest, "munarium:manifest:v2"));
    r["policy_digest"] = json!(pin(&h.snapshot.policy, "munarium:decision-policy:v1"));
    h.snapshot.binding["manifest_digest"] = r["manifest_digest"].clone();
    h.snapshot.binding["policy_digest"] = r["policy_digest"].clone();
    e.output["predicates"] = json!({predicate.clone():true});
    let receipt = run(&r, &mut h, &mut e).unwrap();
    assert_eq!(receipt.decision()["outcome"], "approval-required");
    assert_eq!(receipt.decision()["consequence"], "C3");
    assert_eq!(
        receipt.decision()["obligations"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        receipt.decision()["obligations"][0]["policy_digest"],
        r["policy_digest"]
    );
    e.output["predicates"][&predicate] = json!(false);
    assert_eq!(
        run(&r, &mut h, &mut e).unwrap().decision()["consequence"],
        "C1"
    );
    h.snapshot.manifest["modifiers"][0]["raise_to"] = json!("C0");
    r["manifest_digest"] = json!(pin(&h.snapshot.manifest, "munarium:manifest:v2"));
    h.snapshot.binding["manifest_digest"] = r["manifest_digest"].clone();
    assert_eq!(
        run(&r, &mut h, &mut e).unwrap().decision()["reasons"],
        json!(["manifest-unavailable"])
    );
}
