// SPDX-License-Identifier: Apache-2.0
//! Bounded dynamic release materialization from independently admitted owner inputs.
//! This library issues neither approval nor grant and does not authenticate its callers.
use crate::{
    activation_wire::{self as wire, Error, Result},
    decision::{self, Engine},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Trusted owner inputs assembled by the authenticated service, never a request DTO.
pub struct Authority {
    /// Enrolled task/request template with current qualified identity and context.
    pub template: Value,
    /// Current enrolled requester identities used to refuse self-approval.
    pub requester_chain: Vec<Value>,
    /// Registry-verified manifest at the exact currently activated digest.
    pub manifest: Value,
    /// Current activated policy artifact, including native pins and parameter schema.
    pub policy: Value,
    /// Canonical immutable test-result bytes from current Server-signed enrollment.
    pub evidence_source: String,
    /// Current bounded UTC observation for freshness checks.
    pub now: u64,
}

/// Pin the native evaluator profile in the existing qualified action context.
pub fn evaluator_profile(policy: &Value) -> Result<String> {
    wire::digest(
        "evaluator-profile",
        &json!({"engine":policy["engine"],
        "version":policy["engine_version"],"binary":policy["engine_digest"],
        "worker":policy["worker_digest"],"capabilities":policy["capabilities_digest"]}),
    )
}

fn hash_source(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

/// Verify immutable authority bindings and derive the supported test-result evidence.
/// The adapter must additionally authenticate owners and verify their live heads.
pub fn validate(auth: &Authority, parameters: &Value) -> Result<Value> {
    let r = &auth.template;
    let scope = &r["operation"]["scope"];
    wire::shape(r, "action-request")?;
    wire::scoped(r, scope)?;
    wire::scoped(&json!(auth.requester_chain), scope)?;
    let p = &auth.policy;
    let m = &auth.manifest;
    let context = &r["context"];
    let keys = [
        "profile",
        "engine",
        "engine_version",
        "engine_digest",
        "worker_digest",
        "capabilities_digest",
        "code",
        "parameter_schema",
        "rule_obligations",
    ];
    if p.as_object()
        .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
        || p["profile"] != "stage2-release-evaluation-v1"
        || p["engine"] != "opa"
        || context["policy_digest"]
            != decision::digest("munarium:decision-policy:v1", wire::raw(p)?.as_bytes())
        || context["manifest_digest"]
            != decision::digest("munarium:manifest:v2", wire::raw(m)?.as_bytes())
        || context["evaluator_profile_digest"] != evaluator_profile(p)?
        || context["mode"] != "enforce"
        || context["valid_from"]
            .as_u64()
            .is_none_or(|v| auth.now < v.saturating_add(2))
        || context["expires_at"]
            .as_u64()
            .is_none_or(|v| auth.now.saturating_add(2) >= v)
        || !auth.requester_chain.contains(&r["intent"]["actor"])
        || !auth.requester_chain.contains(&r["intent"]["origin"])
        || m["schema_version"] != 2
        || m["profile"] != "registry-manifest-v2"
        || m["tenant"] != scope["tenant"]
        || m["operation_id"] != "release.publish_approved_artifact"
        || r["intent"]["capability_operation"] != m["operation_id"]
        || m["environment"] != "disposable"
        || r["intent"]["environment"] != m["environment"]
        || m["target_id"] != r["intent"]["target"]["id"]
        || m["credential_audience"] != r["intent"]["target"]["id"]
        || m["base_consequence"] != "C2"
        || m["effect"] != "external-effect"
        || m["idempotency"] != "operation-key"
        || m["compensation"] != "none"
        || m["modifiers"] != json!([])
        || m["required_obligations"] != json!(["distinct-approval"])
        || r["intent"]["attachments"] != json!([])
    {
        return Err(Error::Refused);
    }
    let schema = &p["parameter_schema"];
    let schema_digest = decision::digest(
        "munarium:capability-schema:v1",
        wire::raw(schema)?.as_bytes(),
    );
    if m["parameter_schema_digest"] != schema_digest
        || r["intent"]["parameter_schema_digest"] != schema_digest
        || parameters.as_object().is_none_or(|v| {
            v.len() != 2 || !v.contains_key("artifact_digest") || !v.contains_key("destination")
        })
        || schema["additionalProperties"] != false
        || parameters["destination"] != r["intent"]["parameters"]["destination"]
        || !jsonschema::validator_for(schema)
            .map_err(|_| Error::Invalid)?
            .is_valid(parameters)
    {
        return Err(Error::Refused);
    }
    let evidence = context["evidence"].as_array().ok_or(Error::Refused)?;
    if evidence.len() != 1 {
        return Err(Error::Refused);
    }
    let e = &evidence[0];
    let source = wire::parse(&auth.evidence_source)?;
    if e["content_digest"] != hash_source(auth.evidence_source.as_bytes())
        || e["source"]["kind"] != "evidence"
        || e["revision"].as_u64().is_none_or(|v| v == 0)
        || e["derivation"] != "test-result"
        || e["derivation_version"] != 1
        || e["field"] != "tests.passed"
        || e["trust"] != "verified"
        || e["verifier"]["kind"] != "authority"
        || e["observed_at"]
            .as_u64()
            .is_none_or(|v| auth.now < v.saturating_add(2))
        || e["expires_at"]
            .as_u64()
            .is_none_or(|v| auth.now.saturating_add(2) >= v)
        || source["artifact_digest"] != parameters["artifact_digest"]
        || !source["tests.passed"].is_boolean()
    {
        return Err(Error::Refused);
    }
    Ok(json!({"tests_passed":source["tests.passed"]}))
}

/// Evaluate validated parameters and produce an immutable Stage 2 source/decision.
/// Any forbid wins; mandatory obligations survive permits. No execution is enabled.
pub fn materialize(auth: &Authority, parameters: &Value, engine: &mut dyn Engine) -> Result<Value> {
    let evidence = validate(auth, parameters)?;
    let p = &auth.policy;
    if p["engine"] != engine.name()
        || p["engine_version"] != engine.version()
        || p["engine_digest"] != engine.digest()
    {
        return Err(Error::Refused);
    }
    let mut r = auth.template.clone();
    r["intent"]["parameters"] = parameters.clone();
    r["intent_digest"] = json!(wire::digest("intent", &r["intent"])?);
    r["context_digest"] = json!(wire::digest("context", &r["context"])?);
    wire::shape(&r, "action-request")?;
    let output = engine
        .evaluate(p, &json!({"request":r,"evidence":evidence}))
        .map_err(|_| Error::Unavailable)?;
    let keys = ["allow", "forbid", "rules", "predicates", "diagnostics"];
    if output
        .as_object()
        .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
        || !output["allow"].is_boolean()
        || !output["forbid"].is_boolean()
        || output["diagnostics"] != json!([])
        || output["predicates"] != json!({})
    {
        return Err(Error::Refused);
    }
    let rules = output["rules"].as_array().ok_or(Error::Refused)?;
    let mappings = p["rule_obligations"].as_object().ok_or(Error::Refused)?;
    if mappings.is_empty() || mappings.values().any(|v| v != "distinct-approval") {
        return Err(Error::Refused);
    }
    let mut seen = BTreeSet::new();
    for rule in rules {
        let name = rule.as_str().ok_or(Error::Refused)?;
        if !seen.insert(name) || !mappings.contains_key(name) {
            return Err(Error::Refused);
        }
    }
    let allowed = output["allow"] == true && output["forbid"] == false;
    if allowed && rules.is_empty() {
        return Err(Error::Refused);
    }
    let obligations = if allowed {
        json!([
            {"kind":"distinct-approval","owner":"council","policy_digest":r["context"]["policy_digest"]},
            {"kind":"mandatory-recording","owner":"server","phase":"before-send"},
            {"kind":"action-capacity","owner":"gate","target":r["intent"]["target"],"limit":2,"window_seconds":3600},
            {"kind":"credential-custody","owner":"warden","audience":r["intent"]["target"]}
        ])
    } else {
        json!([])
    };
    let d = json!({"schema_version":1,"type":"action-decision","profile":"stage2-single-cell-v1",
        "operation":r["operation"],"attempt":r["attempt"],"request_digest":wire::digest("action-request", &r)?,
        "context_digest":r["context_digest"],"outcome":if allowed {"approval-required"} else {"denied"},
        "reason_codes":[if allowed {"policy-permit"} else {"policy-deny"}],"obligations":obligations});
    wire::shape(&d, "action-decision")?;
    Ok(
        json!({"request":r,"decision":d,"current_context":r["context"],"requester_chain":auth.requester_chain}),
    )
}
