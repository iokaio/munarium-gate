// SPDX-License-Identifier: Apache-2.0
//! Private, bounded retention of qualified service read identity, never owner evidence.
use super::{Error, decision, principal};
use serde_json::json;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

struct Entry {
    chain: Vec<String>,
    admitted: Instant,
}

#[derive(Default)]
pub(super) struct Cache {
    entries: BTreeMap<String, Entry>,
}

pub(super) fn key(
    authority: &[u8],
    provider: &[u8],
    deployment: &str,
    tenant: &str,
    presenter: &str,
    audience: &str,
) -> String {
    let state = decision::digest("munarium:private-read-authority:v1", authority);
    let input = decision::digest("munarium:private-read-provider:v1", provider);
    decision::digest(
        "munarium:private-registry-read-cache:v1",
        serde_json::to_vec(&(state, input, deployment, tenant, presenter, audience))
            .expect("string tuple serialization")
            .as_slice(),
    )
}

fn qualified(chain: &[String], trust: &principal::Trust) -> Result<(), Error> {
    let p = principal::verify(chain, trust).map_err(|_| Error::Identity)?;
    let payload = chain
        .last()
        .and_then(|token| token.split('.').nth(1))
        .ok_or(Error::Identity)?;
    // The verifier above has already checked canonical encoding and signatures.
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
        .map_err(|_| Error::Identity)?;
    let claims: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| Error::Identity)?;
    if !p.permits("read", &format!("registry:{}", trust.tenant))
        || claims["scopes"] != json!(["read"])
        || claims["resources"] != json!([format!("registry:{}", trust.tenant)])
        || p.expires()
            .checked_sub(trust.now)
            .is_none_or(|left| left < 10)
    {
        return Err(Error::Identity);
    }
    Ok(())
}

impl Cache {
    pub(super) fn get(&self, key: &str, trust: &principal::Trust) -> Option<Vec<String>> {
        let entry = self.entries.get(key)?;
        if entry.admitted.elapsed() > Duration::from_secs(20)
            || qualified(&entry.chain, trust).is_err()
        {
            return None;
        }
        Some(entry.chain.clone())
    }

    pub(super) fn insert(
        &mut self,
        key: String,
        chain: Vec<String>,
        trust: &principal::Trust,
    ) -> Result<Vec<String>, Error> {
        qualified(&chain, trust)?;
        if self.entries.len() >= 32 {
            self.entries.clear();
        }
        self.entries.insert(
            key,
            Entry {
                chain: chain.clone(),
                admitted: Instant::now(),
            },
        );
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture(expires: i64) -> (Vec<String>, principal::Trust) {
        let signer = SigningKey::from_bytes(&[19; 32]); // Isolated unit-only identity.
        let header = json!({"alg":"Ed25519","kid":"test","typ":"munarium-principal+jws"});
        let payload = json!({"schema_version":1,"deployment":"test-cell","tenant":"fictional",
            "issuer":"warden","audience":"registry","origin":"gate","actor":"gate","origin_kind":"service",
            "service":"gate","purpose":"decision","scopes":["read"],"resources":["registry:fictional"],
            "iat":1000,"nbf":1000,"exp":expires,"parent_digest":null,"bootstrap":null});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let token = format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign(message.as_bytes()).to_bytes())
        );
        let trust = principal::Trust {
            deployment: "test-cell".into(),
            tenant: "fictional".into(),
            audience: "registry".into(),
            peer_service: "gate".into(),
            now: 1003,
            available: true,
            keys: BTreeMap::from([(
                "test".into(),
                principal::TrustedKey {
                    public_key: signer.verifying_key().to_bytes(),
                    issuer: "warden".into(),
                    decision: true,
                },
            )]),
            delegations: vec![],
            task_digest: format!("sha256:{}", "a".repeat(64)),
            policy_digest: format!("sha256:{}", "b".repeat(64)),
            not_before: 980,
            expires: 1200,
            scopes: vec!["read".into()],
            resources: vec!["registry:fictional".into()],
            maximum_depth: 0,
        };
        (vec![token], trust)
    }

    #[test]
    fn signed_current_identity_is_reused_without_renewal_or_persistence() {
        let (chain, trust) = fixture(1060);
        let mut cache = Cache::default();
        cache.insert("slot".into(), chain.clone(), &trust).unwrap();
        let admitted = cache.entries["slot"].admitted;
        assert_eq!(cache.get("slot", &trust), Some(chain));
        assert_eq!(cache.entries["slot"].admitted, admitted);
        assert!(Cache::default().get("slot", &trust).is_none());
        cache.entries.get_mut("slot").unwrap().admitted = Instant::now() - Duration::from_secs(21);
        assert!(cache.get("slot", &trust).is_none());
    }

    #[test]
    fn current_signature_scope_key_and_expiry_are_not_cached_permissions() {
        let (chain, trust) = fixture(1060);
        let mut cache = Cache::default();
        cache.insert("slot".into(), chain, &trust).unwrap();
        let mut changed = trust.clone();
        changed.available = false;
        assert!(cache.get("slot", &changed).is_none());
        changed = trust.clone();
        changed.tenant = "other".into();
        assert!(cache.get("slot", &changed).is_none());
        changed = trust.clone();
        changed.peer_service = "other".into();
        assert!(cache.get("slot", &changed).is_none());
        changed = trust.clone();
        changed.keys.clear();
        assert!(cache.get("slot", &changed).is_none());
        changed = trust.clone();
        changed.resources = vec!["registry:other".into()];
        assert!(cache.get("slot", &changed).is_none());
        changed = trust;
        changed.now = 1051;
        assert!(cache.get("slot", &changed).is_none());
        let (mut malformed, trust) = fixture(1060);
        malformed[0].push('x');
        assert!(cache.insert("bad".into(), malformed, &trust).is_err());
    }

    #[test]
    fn authority_provider_and_recipient_changes_cannot_hit_an_earlier_entry() {
        let initial = key(
            b"state-1",
            b"synthetic-provider-1",
            "cell",
            "tenant",
            "gate",
            "registry",
        );
        for other in [
            key(
                b"state-2",
                b"synthetic-provider-1",
                "cell",
                "tenant",
                "gate",
                "registry",
            ),
            key(
                b"state-1",
                b"synthetic-provider-2",
                "cell",
                "tenant",
                "gate",
                "registry",
            ),
            key(
                b"state-1",
                b"synthetic-provider-1",
                "cell",
                "other",
                "gate",
                "registry",
            ),
            key(
                b"state-1",
                b"synthetic-provider-1",
                "cell",
                "tenant",
                "other",
                "registry",
            ),
            key(
                b"state-1",
                b"synthetic-provider-1",
                "cell",
                "tenant",
                "gate",
                "other",
            ),
        ] {
            assert_ne!(initial, other);
        }
    }

    #[test]
    fn broader_valid_identity_cannot_be_retained_as_read_identity() {
        let (chain, mut trust) = fixture(1060);
        let parts: Vec<_> = chain[0].split('.').collect();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        payload["scopes"] = json!(["read", "propose"]);
        trust.scopes.push("propose".into());
        let message = format!(
            "{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let token = format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(
                SigningKey::from_bytes(&[19; 32])
                    .sign(message.as_bytes())
                    .to_bytes()
            )
        );
        let broader = vec![token];
        assert!(principal::verify(&broader, &trust).is_ok());
        assert!(
            Cache::default()
                .insert("slot".into(), broader, &trust)
                .is_err()
        );
    }
}
