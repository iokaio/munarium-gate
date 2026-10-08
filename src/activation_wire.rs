// SPDX-License-Identifier: Apache-2.0
//! Closed Stage 2 activation records and independently authenticated evidence.
use serde_json::{Value, json};
use std::sync::LazyLock;
/// Sanitized activation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Malformed or unsupported record.
    Invalid,
    /// Current authority or evidence is missing.
    Refused,
    /// Immutable identity or expected head conflicts.
    Conflict,
    /// Durable storage or an authenticated dependency is unavailable.
    Unavailable,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
/// Bounded activation result.
pub type Result<T> = std::result::Result<T, Error>;
/// Canonicalize only within the unchanged candidate bounds.
pub fn raw(v: &Value) -> Result<String> {
    let s = serde_json::to_string(v).map_err(|_| Error::Invalid)?;
    parse(&s)?;
    Ok(s)
}
/// Parse exact canonical bytes, rejecting duplicates and alternate encodings.
pub fn parse(s: &str) -> Result<Value> {
    crate::decision::parse(s.as_bytes()).map_err(|_| Error::Invalid)
}
/// Candidate domain-separated SHA-256.
pub fn digest(domain: &str, v: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(format!("munarium:stage2:{domain}:v1\0{}", raw(v)?).as_bytes())
    ))
}
static SCHEMA: LazyLock<Option<jsonschema::Validator>> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str::<Value>(include_str!("../contracts/stage2-v1/schema.json")).ok()?,
    )
    .ok()
});
/// Validate a closed candidate record; shape alone conveys no authority.
pub fn shape(v: &Value, kind: &str) -> Result<()> {
    raw(v)?;
    if v["type"] != kind || !SCHEMA.as_ref().ok_or(Error::Unavailable)?.is_valid(v) {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Verify every qualified reference belongs to the admitted scope.
pub fn scoped(v: &Value, scope: &Value) -> Result<()> {
    match v {
        Value::Object(m) => {
            if m.get("scope").is_some_and(|s| s != scope) {
                return Err(Error::Refused);
            }
            for child in m.values() {
                scoped(child, scope)?;
            }
        }
        Value::Array(a) => {
            for child in a {
                scoped(child, scope)?;
            }
        }
        _ => {}
    }
    Ok(())
}
/// Trusted adapter inputs; deliberately not deserializable from a request.
pub struct Authority {
    /// Independently enrolled scope.
    pub scope: Value,
    /// Exact currently ratified transition obtained from Council.
    pub ratified: Value,
    /// Bounded current UTC seconds.
    pub now: u64,
}
/// Validate exact ratification, hashes, scope and current transition window.
pub fn validate(auth: &Authority, t: &Value) -> Result<()> {
    shape(t, "activation")?;
    scoped(t, &auth.scope)?;
    let profile: Value = serde_json::from_str(include_str!("../contracts/stage2-v1/profile.json"))
        .map_err(|_| Error::Unavailable)?;
    if auth.ratified["ratified"] != true
        || auth.ratified["transition"] != *t
        || auth.ratified["transition_digest"] != digest("activation", t)?
        || t["profile_digest"] != digest("profile", &profile)?
        || t["participants"] != profile["participants"]
        || t["participant_set_digest"]
            != digest(
                "participants",
                &json!({"participants":profile["participants"]}),
            )?
        || t["artifact_set_digest"] != digest("artifact-set", &json!({"artifacts":t["artifacts"]}))?
        || t["successor_epoch"].as_u64() <= t["prior_epoch"].as_u64()
        || t["not_before"]
            .as_u64()
            .is_none_or(|n| auth.now < n.saturating_add(2))
        || t["expires_at"]
            .as_u64()
            .is_none_or(|n| auth.now.saturating_add(2) >= n)
    {
        return Err(Error::Refused);
    }
    Ok(())
}
/// Match a receipt to every field of the exact transition and authenticated owner.
pub fn check_receipt(t: &Value, r: &Value, owner: &str, phase: &str) -> Result<()> {
    shape(r, "activation-receipt")?;
    if r["participant"] != owner
        || r["phase"] != phase
        || r["transition_digest"] != digest("activation", t)?
    {
        return Err(Error::Refused);
    }
    for k in [
        "transition",
        "prior_epoch",
        "successor_epoch",
        "artifact_set_digest",
        "participant_set_digest",
    ] {
        if r[k] != t[k] {
            return Err(Error::Refused);
        }
    }
    Ok(())
}
/// Construct a receipt only inside an owner's durable transaction.
pub(crate) fn receipt(t: &Value, owner: &str, phase: &str) -> Result<Value> {
    let mut r = json!({"schema_version":1,"profile":"stage2-single-cell-v1","type":"activation-receipt",
        "participant":owner,"phase":phase,"transition_digest":digest("activation",t)?});
    for k in [
        "transition",
        "prior_epoch",
        "successor_epoch",
        "artifact_set_digest",
        "participant_set_digest",
    ] {
        r[k] = t[k].clone();
    }
    shape(&r, "activation-receipt")?;
    Ok(r)
}
/// Validate current participant head independently of its historical receipt.
pub fn check_head(t: &Value, h: &Value, owner: &str) -> Result<()> {
    if h["scope"] != t["transition"]["scope"]
        || h["participant"] != owner
        || h["epoch"] != t["successor_epoch"]
        || h["artifact_set_digest"] != t["artifact_set_digest"]
    {
        return Err(Error::Refused);
    }
    Ok(())
}
/// Validate the initial enrollment without inventing an existing artifact history.
pub fn initial(scope: &Value, epoch: u64, digest: &str) -> Result<()> {
    let o = scope.as_object().ok_or(Error::Invalid)?;
    if o.len() != 4
        || ["domain", "tenant", "deployment", "cell"].iter().any(|k| {
            o.get(*k).and_then(Value::as_str).is_none_or(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s.as_bytes()[0].is_ascii_alphanumeric()
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b":._/-".contains(&b))
            })
        })
        || epoch == 0
        || epoch > 9007199254740991
        || digest.len() != 71
        || !digest.starts_with("sha256:")
        || !digest.as_bytes()[7..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
