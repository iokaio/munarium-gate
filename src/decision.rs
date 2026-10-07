// SPDX-License-Identifier: Apache-2.0
//! Experimental Stage 1 evaluation. No grant, connector or dispatch dependency.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Sanitized refusal categories, never raw credentials or foreign evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed, ambiguous, noncanonical or incompatible request.
    Request,
    /// Identity or tenant binding was not verified.
    Identity,
    /// Manifest is missing, incompatible, retired or inactive.
    Manifest,
    /// Policy, epoch or mode differs from current admitted state.
    Activation,
    /// Required evidence is absent, untrusted, substituted or out of scope.
    Lineage,
    /// Parameters or attachment bytes do not match the admitted schema/references.
    Parameters,
    /// Evaluator failure, diagnostics, unsupported rule or invalid output.
    Evaluator,
    /// Required record was not acknowledged with its exact bindings.
    Recording,
    /// Existing operation identity is bound to different bytes.
    Conflict,
}
impl Error {
    /// Stable non-sensitive refusal reason.
    pub fn code(self) -> &'static str {
        match self {
            Self::Request => "invalid-request",
            Self::Identity => "identity-refused",
            Self::Manifest => "manifest-unavailable",
            Self::Activation => "activation-mismatch",
            Self::Lineage => "lineage-unavailable",
            Self::Parameters => "invalid-parameters",
            Self::Evaluator => "evaluation-error",
            Self::Recording => "recording-unavailable",
            Self::Conflict => "operation-conflict",
        }
    }
}

/// Hash exact bytes in an explicitly selected domain.
pub fn digest(domain: &str, raw: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(raw);
    format!("sha256:{:x}", h.finalize())
}

/// Receiver narrowing: accept canonical JSON only, with bounded profile values.
/// Clients canonicalize before submission. Duplicate keys cannot survive byte equality.
pub fn parse(raw: &[u8]) -> Result<Value, Error> {
    if raw.len() > 65536 {
        return Err(Error::Request);
    }
    let v: Value = serde_json::from_slice(raw).map_err(|_| Error::Request)?;
    fn valid(v: &Value, depth: usize) -> bool {
        match v {
            Value::Object(m) => {
                depth < 16
                    && m.keys().all(|k| k.is_ascii())
                    && m.values().all(|v| valid(v, depth + 1))
            }
            Value::Array(a) => depth < 16 && a.iter().all(|v| valid(v, depth + 1)),
            Value::Number(n) => n
                .as_i64()
                .is_some_and(|n| (-9007199254740991..=9007199254740991).contains(&n)),
            _ => true,
        }
    }
    if !v.is_object() || !valid(&v, 0) || serde_json::to_vec(&v).map_err(|_| Error::Request)? != raw
    {
        return Err(Error::Request);
    }
    Ok(v)
}

fn foundation() -> &'static Value {
    static S: OnceLock<Value> = OnceLock::new();
    S.get_or_init(|| {
        serde_json::from_str(include_str!("../contracts/stage1/foundation.schema.json"))
            .expect("pinned schema")
    })
}
/// Validate a record against the unchanged foundation candidate.
pub fn validate_record(kind: &str, v: &Value) -> Result<(), Error> {
    let root = foundation();
    if root["$defs"].get(kind).is_none() {
        return Err(Error::Request);
    }
    let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":root["$defs"],"$ref":format!("#/$defs/{kind}")});
    let validator = jsonschema::validator_for(&schema).map_err(|_| Error::Request)?;
    if !validator.is_valid(v) {
        return Err(Error::Request);
    }
    Ok(())
}

/// Principal facts returned only by the host's current receiving-side verifier.
/// This is a trusted adapter result, never deserialized from the proposal.
pub struct Principal {
    /// Verified original actor for authenticated recovery ownership.
    pub origin: String,
    /// Verified current actor for authenticated recovery ownership.
    pub actor: String,
    /// Verified agent or service origin kind.
    pub origin_kind: String,
    /// Actual tenant selected by authenticated routing.
    pub tenant: String,
    /// Exact verified original assertion digest.
    pub digest: String,
    /// Signed scopes intersected with task and policy.
    pub scopes: Vec<String>,
    /// Signed exact registered target resources.
    pub resources: Vec<String>,
}

/// Current snapshot assembled independently by the trusted host.
/// No constructor accepts agent-provided JSON as proof of admission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Complete Registry-verified manifest payload.
    pub manifest: Value,
    /// Exact signed envelope digest verified by Registry.
    pub artifact_digest: String,
    /// Independently admitted binding: tenant, manifest/artifact/policy digest,
    /// target_id, environment, activation_epoch and mode, plus available=true.
    pub binding: Value,
    /// Complete immutable policy artifact; code, schema and obligation mapping.
    pub policy: Value,
    /// Immutable parameter schema checked by Registry's restricted profile.
    pub parameter_schema: Value,
    /// Authoritative lineage metadata paired with exact source bytes and derived value.
    pub evidence: Vec<Evidence>,
    /// Already admitted attachment bytes, keyed by digest and media type.
    pub attachments: Vec<Attachment>,
}
/// Independently resolved source and derivation result.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Unchanged foundation lineage record.
    pub lineage: Value,
    /// Exact source bytes whose SHA-256 is bound by the lineage.
    pub source: Vec<u8>,
    /// Verified derivation output, not a value supplied by the agent.
    pub value: Value,
}
/// Resolved immutable attachment.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    /// Exact media type from admitted storage.
    pub media_type: String,
    /// Original immutable content bytes.
    pub bytes: Vec<u8>,
}

/// Privileged adapters. Implementations authenticate all remote hops and fail on stale state.
pub trait Host {
    /// Verify original evidence for this request against current peer/tenant/authority.
    fn principal(&mut self, chain: &[String]) -> Result<Principal, Error>;
    /// Resolve current Registry, policy and evidence state for the verified tenant.
    fn snapshot(&mut self, tenant: &str, request: &Value) -> Result<Snapshot, Error>;
    /// Record the proposal and result; validate Server's exact event acknowledgements.
    fn record(&mut self, request: &Value, decision: &Value, replay: &[u8]) -> Result<(), Error>;
}

/// A bounded native evaluator worker with pinned implementation identity.
pub trait Engine {
    /// Exactly `opa` or `cedar` under the candidate contract.
    fn name(&self) -> &'static str;
    /// Exact engine version.
    fn version(&self) -> &str;
    /// Digest of the admitted executable/worker, never caller-selected.
    fn digest(&self) -> &str;
    /// Return one closed result: allow/forbid booleans, determining rule IDs,
    /// modifier predicate booleans and an empty diagnostics array on success.
    fn evaluate(&mut self, policy: &Value, input: &Value) -> Result<Value, Error>;
}

/// Recorded result with an immutable replay bundle. It carries no execution methods.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor: Option<RecordedActor>,
    decision: Value,
    request: Value,
    snapshot: Option<Snapshot>,
    input: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedActor {
    origin: String,
    actor: String,
    origin_kind: String,
}
impl Receipt {
    /// Whether a currently verified caller owns this recorded operation.
    pub fn belongs_to(&self, origin: &str, actor: &str, origin_kind: &str) -> bool {
        self.actor.as_ref().is_some_and(|owner| {
            owner.origin == origin && owner.actor == actor && owner.origin_kind == origin_kind
        })
    }
    /// Original canonical request retained for exact recovery conflict checks.
    pub fn request(&self) -> &Value {
        &self.request
    }
    /// Canonical replay artifact for protected storage, including exact resolved inputs.
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        let value = serde_json::to_value(self).map_err(|_| Error::Recording)?;
        let raw = encoded(&value);
        if raw.len() > 8 * 1024 * 1024 {
            return Err(Error::Recording);
        }
        Ok(raw)
    }
    /// Restore a replay artifact using a digest independently obtained from trusted Server storage.
    /// This checks integrity, not reader authorization or current execution authority.
    pub fn restore(raw: &[u8], expected_digest: &str) -> Result<Self, Error> {
        if raw.len() > 8 * 1024 * 1024
            || digest("munarium:decision-replay:v1", raw) != expected_digest
        {
            return Err(Error::Recording);
        }
        let receipt: Self = serde_json::from_slice(raw).map_err(|_| Error::Recording)?;
        if receipt.export()? != raw {
            return Err(Error::Recording);
        }
        parse(&encoded(&receipt.request))?;
        validate_record("request", &receipt.request)?;
        let is_decision = receipt.decision.get("outcome").is_some();
        validate_record(
            if is_decision { "decision" } else { "refusal" },
            &receipt.decision,
        )?;
        if receipt.decision["tenant"] != receipt.request["tenant"]
            || receipt.decision["operation_id"] != receipt.request["operation_id"]
            || receipt.decision["request_digest"] != request_hash(&receipt.request)
        {
            return Err(Error::Recording);
        }
        if is_decision
            && prepare(
                &receipt.request,
                receipt.snapshot.as_ref().ok_or(Error::Recording)?,
            )? != receipt.input
        {
            return Err(Error::Recording);
        }
        Ok(receipt)
    }
    /// Exact recorded decision or refusal.
    pub fn decision(&self) -> &Value {
        &self.decision
    }
    /// Re-evaluate pinned bytes without fetching new inputs, recording or dispatching.
    pub fn replay(&self, engine: &mut impl Engine) -> Result<Value, Error> {
        if self.decision.get("outcome").is_none() {
            return Ok(self.decision.clone());
        }
        let decision = evaluate(
            &self.request,
            self.snapshot.as_ref().ok_or(Error::Evaluator)?,
            &self.input,
            engine,
        )?;
        if decision != self.decision {
            return Err(Error::Evaluator);
        }
        Ok(decision)
    }
}

fn raw_hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn encoded(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("JSON value")
}
fn request_hash(v: &Value) -> String {
    digest("munarium:decision-request:v1", &encoded(v))
}
fn failure(r: &Value, e: Error) -> Value {
    json!({"schema_version":1,"tenant":r["tenant"],"operation_id":r["operation_id"],"request_digest":request_hash(r),"reasons":[e.code()]})
}

/// Independently validate, evaluate and record one decision-only proposal.
/// No success is returned if required recording fails.
pub fn decide(
    raw: &[u8],
    chain: &[String],
    host: &mut impl Host,
    engine: &mut impl Engine,
) -> Result<Receipt, Error> {
    let request = parse(raw)?;
    validate_record("request", &request)?;
    let principal = host.principal(chain)?;
    if request["tenant"] != principal.tenant
        || request["principal_digest"] != principal.digest
        || !principal.scopes.iter().any(|s| s == "evaluate")
        || !principal
            .resources
            .iter()
            .any(|r| Some(r.as_str()) == request["target_id"].as_str())
    {
        return Err(Error::Identity);
    }
    let fetched = host.snapshot(&principal.tenant, &request);
    let result = match &fetched {
        Ok(snapshot) => prepare(&request, snapshot)
            .and_then(|input| evaluate(&request, snapshot, &input, engine).map(|d| (input, d))),
        Err(e) => Err(*e),
    };
    let (input, decision) = match result {
        Ok(v) => v,
        Err(e) => (json!({}), failure(&request, e)),
    };
    let receipt = Receipt {
        actor: Some(RecordedActor {
            origin: principal.origin,
            actor: principal.actor,
            origin_kind: principal.origin_kind,
        }),
        request,
        snapshot: fetched.ok(),
        input,
        decision,
    };
    host.record(&receipt.request, &receipt.decision, &receipt.export()?)
        .map_err(|_| Error::Recording)?;
    Ok(receipt)
}

fn prepare(r: &Value, s: &Snapshot) -> Result<Value, Error> {
    let m = &s.manifest;
    let b = &s.binding;
    if m["schema_version"] != 2
        || m["profile"] != "registry-manifest-v2"
        || m["tenant"] != r["tenant"]
        || digest("munarium:manifest:v2", &encoded(m)) != r["manifest_digest"]
    {
        return Err(Error::Manifest);
    }
    for field in ["tenant", "target_id", "environment", "capability_id"] {
        if m[field] != r[field] {
            return Err(Error::Manifest);
        }
    }
    if b["available"] != true || b["artifact_digest"] != s.artifact_digest {
        return Err(Error::Activation);
    }
    for field in [
        "tenant",
        "target_id",
        "environment",
        "manifest_digest",
        "policy_digest",
        "activation_epoch",
        "mode",
    ] {
        if b[field] != r[field] {
            return Err(Error::Activation);
        }
    }
    if digest("munarium:decision-policy:v1", &encoded(&s.policy)) != r["policy_digest"] {
        return Err(Error::Activation);
    }
    if digest(
        "munarium:capability-schema:v1",
        &encoded(&s.parameter_schema),
    ) != m["parameter_schema_digest"]
    {
        return Err(Error::Parameters);
    }
    // Registry admits only bounded schemas without references. Recheck that boundary
    // before invoking a validator so a host cannot accidentally enable remote fetching.
    fn no_refs(v: &Value) -> bool {
        match v {
            Value::Object(o) => !o.contains_key("$ref") && o.values().all(no_refs),
            Value::Array(a) => a.iter().all(no_refs),
            _ => true,
        }
    }
    if !no_refs(&s.parameter_schema)
        || !jsonschema::validator_for(&s.parameter_schema)
            .map_err(|_| Error::Parameters)?
            .is_valid(&r["parameters"])
    {
        return Err(Error::Parameters);
    }
    let mut total = 0u64;
    for a in r["attachments"].as_array().ok_or(Error::Parameters)? {
        let n = a["bytes"].as_u64().ok_or(Error::Parameters)?;
        total = total.checked_add(n).ok_or(Error::Parameters)?;
        let matches = s
            .attachments
            .iter()
            .filter(|v| {
                raw_hash(&v.bytes) == a["digest"]
                    && v.media_type == a["media_type"]
                    && v.bytes.len() as u64 == n
            })
            .count();
        if matches != 1 || total > 1048576 {
            return Err(Error::Parameters);
        }
    }
    let mut fields = serde_json::Map::new();
    let required = m["required_inputs"].as_array().ok_or(Error::Lineage)?;
    let uses = s.policy["inputs"].as_array().ok_or(Error::Lineage)?;
    for spec in required.iter().chain(uses) {
        let matches: Vec<_> = s
            .evidence
            .iter()
            .filter(|e| e.lineage["field_path"] == spec["field_path"])
            .collect();
        if matches.len() != 1 || spec["permitted_use"] != "decision" {
            return Err(Error::Lineage);
        }
        let e = matches[0];
        let l = &e.lineage;
        validate_record("lineage", l).map_err(|_| Error::Lineage)?;
        if l["tenant"] != r["tenant"]
            || l["trust"] != "verified"
            || l["policy_digest"] != r["policy_digest"]
            || l.as_object().is_none_or(|o| o.values().any(Value::is_null))
            || raw_hash(&e.source) != l["content_digest"]
        {
            return Err(Error::Lineage);
        }
        for key in ["source_id", "derivation_id", "derivation_version"] {
            if l[key] != spec[key] {
                return Err(Error::Lineage);
            }
        }
        if !uses.iter().any(|u| u == spec) {
            return Err(Error::Lineage);
        }
        let name = spec["field_path"].as_str().ok_or(Error::Lineage)?;
        fields.insert(name.into(), e.value.clone());
    }
    // Never include unused or unverified evidence in an allowed result.
    if s.evidence.len() != fields.len() {
        return Err(Error::Lineage);
    }
    Ok(
        json!({"tenant":r["tenant"],"request_digest":request_hash(r),"parameters":r["parameters"],"evidence":fields}),
    )
}

fn evaluate(
    r: &Value,
    s: &Snapshot,
    input: &Value,
    engine: &mut impl Engine,
) -> Result<Value, Error> {
    let p = &s.policy;
    if p["engine"] != engine.name()
        || p["version"] != engine.version()
        || p["engine_digest"] != engine.digest()
    {
        return Err(Error::Evaluator);
    }
    let output = engine.evaluate(p, input)?;
    let keys = ["allow", "forbid", "rules", "predicates", "diagnostics"];
    if output
        .as_object()
        .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
        || !output["allow"].is_boolean()
        || !output["forbid"].is_boolean()
        || output["diagnostics"] != json!([])
    {
        return Err(Error::Evaluator);
    }
    let rules = output["rules"].as_array().ok_or(Error::Evaluator)?;
    if output["allow"] == true && rules.is_empty() {
        return Err(Error::Evaluator);
    }
    let mut seen = std::collections::BTreeSet::new();
    if rules
        .iter()
        .any(|r| r.as_str().is_none_or(|id| !seen.insert(id)))
    {
        return Err(Error::Evaluator);
    }
    let mapping = p["rules"].as_object().ok_or(Error::Evaluator)?;
    let mut obligations = Vec::new();
    for rule in rules {
        let spec = mapping
            .get(rule.as_str().ok_or(Error::Evaluator)?)
            .ok_or(Error::Evaluator)?;
        if !spec.is_null() {
            if spec.as_object().is_none_or(|o| o.len() != 2)
                || spec["kind"] != "distinct-approval"
                || spec["approver_scope"].as_str().is_none()
            {
                return Err(Error::Evaluator);
            }
            let obligation = json!({"kind":"distinct-approval","approver_scope":spec["approver_scope"],"request_digest":request_hash(r),"policy_digest":r["policy_digest"]});
            if !obligations.contains(&obligation) {
                obligations.push(obligation);
            }
        }
    }
    let declared = s.manifest["required_obligations"]
        .as_array()
        .ok_or(Error::Manifest)?;
    for kind in declared {
        if kind != "distinct-approval" {
            return Err(Error::Evaluator);
        }
        let scope = p["manifest_approver_scope"]
            .as_str()
            .ok_or(Error::Evaluator)?;
        let obligation = json!({"kind":kind,"approver_scope":scope,"request_digest":request_hash(r),"policy_digest":r["policy_digest"]});
        if !obligations.contains(&obligation) {
            obligations.push(obligation);
        }
    }
    obligations.sort_by_key(Value::to_string);
    let mut consequence = s.manifest["base_consequence"]
        .as_str()
        .ok_or(Error::Manifest)?
        .to_owned();
    let predicates = output["predicates"].as_object().ok_or(Error::Evaluator)?;
    let modifiers = s.manifest["modifiers"].as_array().ok_or(Error::Manifest)?;
    if predicates.len() != modifiers.len() {
        return Err(Error::Evaluator);
    }
    for modifier in modifiers {
        let pred = modifier["predicate_digest"]
            .as_str()
            .ok_or(Error::Evaluator)?;
        let applies = predicates
            .get(pred)
            .and_then(Value::as_bool)
            .ok_or(Error::Evaluator)?;
        let raised = modifier["raise_to"].as_str().ok_or(Error::Evaluator)?;
        if raised
            <= s.manifest["base_consequence"]
                .as_str()
                .ok_or(Error::Manifest)?
        {
            return Err(Error::Manifest);
        }
        if applies && raised > consequence.as_str() {
            consequence = raised.into();
        }
    }
    let allowed = output["allow"] == true && output["forbid"] == false;
    let outcome = if !allowed {
        obligations.clear();
        "denied"
    } else if !obligations.is_empty() {
        "approval-required"
    } else {
        "decision-only-allow"
    };
    let mut lineage: Vec<_> = s.evidence.iter().map(|e| e.lineage.clone()).collect();
    lineage.sort_by_key(Value::to_string);
    let decision = json!({"schema_version":1,"tenant":r["tenant"],"operation_id":r["operation_id"],"request_digest":request_hash(r),
        "principal_digest":r["principal_digest"],"manifest_digest":r["manifest_digest"],"policy_digest":r["policy_digest"],
        "evaluator":engine.name(),"evaluator_version":engine.version(),"evaluator_digest":engine.digest(),
        "activation_epoch":r["activation_epoch"],"mode":r["mode"],"lineage":lineage,"consequence":consequence,
        "outcome":outcome,"reasons":[if allowed {"policy-permit"} else {"policy-deny"}],"obligations":obligations});
    validate_record("decision", &decision).map_err(|_| Error::Evaluator)?;
    Ok(decision)
}
