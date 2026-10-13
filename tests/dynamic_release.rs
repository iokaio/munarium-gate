// SPDX-License-Identifier: Apache-2.0
//! Semantic dynamic admission controls with a typed fake engine; native coverage is separate.
use munarium_gate::{
    activation_wire as wire,
    decision::{self, Engine, Error},
    dynamic_release::{self as dynamic, Authority},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Evaluator {
    result: Value,
    calls: usize,
}
impl Engine for Evaluator {
    fn name(&self) -> &'static str {
        "opa"
    }
    fn version(&self) -> &str {
        "1.21.1"
    }
    fn digest(&self) -> &str {
        "sha256:668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"
    }
    fn evaluate(&mut self, _: &Value, input: &Value) -> Result<Value, Error> {
        self.calls += 1;
        assert!(input["evidence"]["tests_passed"].is_boolean());
        Ok(self.result.clone())
    }
}
fn evaluator() -> Evaluator {
    Evaluator {
        calls: 0,
        result: json!({"allow":true,"forbid":false,"rules":["permit"],"predicates":{},"diagnostics":[]}),
    }
}
fn authority() -> Authority {
    let vectors: Value =
        serde_json::from_str(include_str!("../contracts/stage2-v1/vectors.json")).unwrap();
    let mut template = vectors["records"]["request"].clone();
    let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
        "properties":{"artifact_digest":{"type":"string"},"destination":{"type":"string"}},
        "required":["artifact_digest","destination"],"additionalProperties":false});
    let schema_digest = decision::digest(
        "munarium:capability-schema:v1",
        wire::raw(&schema).unwrap().as_bytes(),
    );
    let manifest = json!({"schema_version":2,"profile":"registry-manifest-v2","tenant":template["operation"]["scope"]["tenant"],
        "operation_id":"release.publish_approved_artifact","environment":"disposable","target_id":template["intent"]["target"]["id"],
        "credential_audience":template["intent"]["target"]["id"],"base_consequence":"C2","effect":"external-effect","idempotency":"operation-key","compensation":"none","modifiers":[],
        "required_obligations":["distinct-approval"],"parameter_schema_digest":schema_digest});
    let policy = json!({"profile":"stage2-release-evaluation-v1","engine":"opa","engine_version":"1.21.1",
        "engine_digest":evaluator().digest(),"worker_digest":"sha256:worker","capabilities_digest":"sha256:capabilities",
        "code":"synthetic-unit-only","parameter_schema":schema,"rule_obligations":{"permit":"distinct-approval"}});
    template["intent"]["parameter_schema_digest"] = json!(schema_digest);
    template["context"]["policy_digest"] = json!(decision::digest(
        "munarium:decision-policy:v1",
        wire::raw(&policy).unwrap().as_bytes()
    ));
    template["context"]["manifest_digest"] = json!(decision::digest(
        "munarium:manifest:v2",
        wire::raw(&manifest).unwrap().as_bytes()
    ));
    template["context"]["evaluator_profile_digest"] =
        json!(dynamic::evaluator_profile(&policy).unwrap());
    let evidence_source = wire::raw(&json!({"artifact_digest":template["intent"]["parameters"]["artifact_digest"],"tests.passed":true})).unwrap();
    let evidence = &mut template["context"]["evidence"][0];
    evidence["content_digest"] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(evidence_source.as_bytes())
    ));
    evidence["derivation"] = json!("test-result");
    evidence["field"] = json!("tests.passed");
    template["intent_digest"] = json!(wire::digest("intent", &template["intent"]).unwrap());
    template["context_digest"] = json!(wire::digest("context", &template["context"]).unwrap());
    Authority {
        requester_chain: vec![template["intent"]["actor"].clone()],
        template,
        manifest,
        policy,
        evidence_source,
        now: 1000,
    }
}
fn repin(auth: &mut Authority) {
    auth.template["context"]["policy_digest"] = json!(decision::digest(
        "munarium:decision-policy:v1",
        wire::raw(&auth.policy).unwrap().as_bytes()
    ));
    auth.template["context"]["manifest_digest"] = json!(decision::digest(
        "munarium:manifest:v2",
        wire::raw(&auth.manifest).unwrap().as_bytes()
    ));
    auth.template["context"]["evaluator_profile_digest"] =
        json!(dynamic::evaluator_profile(&auth.policy).unwrap());
}

#[test]
fn approved_source_binds_parameters_context_and_all_mandatory_controls() {
    let auth = authority();
    let mut engine = evaluator();
    let source =
        dynamic::materialize(&auth, &auth.template["intent"]["parameters"], &mut engine).unwrap();
    assert_eq!(engine.calls, 1);
    assert_eq!(source["decision"]["outcome"], "approval-required");
    let obligations = source["decision"]["obligations"].as_array().unwrap();
    assert_eq!(obligations.len(), 4);
    assert_eq!(obligations[2]["limit"], 2);
    assert_eq!(
        source["decision"]["request_digest"],
        wire::digest("action-request", &source["request"]).unwrap()
    );
    assert_eq!(source["current_context"], auth.template["context"]);
    assert_eq!(
        source["requester_chain"][0],
        auth.template["intent"]["actor"]
    );
}

#[test]
fn substituted_parameters_and_invalid_owner_inputs_refuse_before_native_evaluation() {
    let base = authority();
    let parameters = base.template["intent"]["parameters"].clone();
    let mut wrong = parameters.clone();
    wrong["artifact_digest"] = json!("sha256:substituted");
    let mut engine = evaluator();
    assert!(dynamic::materialize(&base, &wrong, &mut engine).is_err());
    wrong = parameters.clone();
    wrong["destination"] = json!("other-target");
    assert!(dynamic::materialize(&base, &wrong, &mut engine).is_err());
    for change in 0..12 {
        let mut auth = authority();
        match change {
            0 => auth.evidence_source.push(' '),
            1 => auth.template["context"]["evidence"][0]["trust"] = json!("unverified"),
            2 => auth.template["context"]["evidence"][0]["expires_at"] = json!(1001),
            3 => auth.template["context"]["evidence"][0]["derivation"] = json!("unknown"),
            4 => auth.template["context"]["mode"] = json!("observe"),
            5 => auth.requester_chain.clear(),
            6 => auth.manifest["required_obligations"] = json!(["unknown"]),
            7 => auth.manifest["tenant"] = json!("foreign"),
            8 => auth.manifest["modifiers"] = json!([{"unknown":true}]),
            9 => auth.policy["engine_digest"] = json!("sha256:substituted"),
            10 => auth.template["context"]["policy_digest"] = json!("sha256:substituted"),
            _ => auth.template["context"]["evidence"] = json!([]),
        }
        if matches!(change, 6..=9) {
            repin(&mut auth);
        }
        assert!(
            dynamic::materialize(&auth, &parameters, &mut engine).is_err(),
            "case {change}"
        );
    }
    assert_eq!(engine.calls, 0);
}

#[test]
fn deny_and_forbid_have_no_executable_obligations() {
    let auth = authority();
    for (allow, forbid) in [(false, false), (true, true)] {
        let mut engine = evaluator();
        engine.result["allow"] = json!(allow);
        engine.result["forbid"] = json!(forbid);
        let source =
            dynamic::materialize(&auth, &auth.template["intent"]["parameters"], &mut engine)
                .unwrap();
        assert_eq!(source["decision"]["outcome"], "denied");
        assert_eq!(source["decision"]["obligations"], json!([]));
    }
}

#[test]
fn ambiguous_native_results_and_unknown_rule_obligations_refuse() {
    let parameters = authority().template["intent"]["parameters"].clone();
    for output in [
        json!({"allow":true}),
        json!({"allow":true,"forbid":false,"rules":[],"predicates":{},"diagnostics":[]}),
        json!({"allow":true,"forbid":false,"rules":["unknown"],"predicates":{},"diagnostics":[]}),
        json!({"allow":true,"forbid":false,"rules":["permit","permit"],"predicates":{},"diagnostics":[]}),
        json!({"allow":true,"forbid":false,"rules":["permit"],"predicates":{},"diagnostics":["error"]}),
    ] {
        let mut engine = evaluator();
        engine.result = output;
        assert!(dynamic::materialize(&authority(), &parameters, &mut engine).is_err());
    }
    let mut auth = authority();
    auth.policy["rule_obligations"]["permit"] = json!("unknown");
    repin(&mut auth);
    assert!(dynamic::materialize(&auth, &parameters, &mut evaluator()).is_err());
}
