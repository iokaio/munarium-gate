// SPDX-License-Identifier: Apache-2.0
//! Authenticated activation adapter. Caller receipts are checked against participant lookups.
use super::*;
use munarium_gate::{
    activation::{Evidence, Store},
    activation_wire::{self as wire, Authority, Error as ActivationError},
};
use std::collections::BTreeSet;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub database_url_file: PathBuf,
    pub council_endpoint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    scope: Value,
    coordinator: String,
    readers: BTreeSet<String>,
    initial_epoch: u64,
    initial_artifact_set_digest: String,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Flush,
    Pause { transition: String },
    PauseLookup { transition_id: String },
    ApplyActivation { transition: String },
    ActivationLookup { transition_id: String },
    ActivationHead,
    Resume { completion: Value },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant: String,
    action: Operation,
}
pub(super) async fn open(config: &Option<Config>) -> Result<Option<Store>, Failure> {
    let Some(c) = config else { return Ok(None) };
    if !c.database_url_file.is_absolute() || !c.council_endpoint.starts_with("https://") {
        return Err(Failure::Configuration);
    }
    let raw = std::fs::read_to_string(&c.database_url_file).map_err(|_| Failure::Configuration)?;
    if raw.len() > 8192 {
        return Err(Failure::Configuration);
    }
    Store::open(raw.trim())
        .await
        .map(Some)
        .map_err(|_| Failure::Unavailable)
}
async fn post(runtime: &Runtime, endpoint: &str, body: Value) -> Result<Value, ActivationError> {
    if !endpoint.starts_with("https://") {
        return Err(ActivationError::Refused);
    }
    let r = runtime
        .client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|_| ActivationError::Unavailable)?;
    service_transport::json_response(r, 262144)
        .await
        .map_err(|_| ActivationError::Unavailable)
}
async fn admitted(runtime: &Runtime, peer: &Peer, body: &[u8]) -> Result<Value, ActivationError> {
    let _permit = runtime
        .activation_permits
        .try_acquire()
        .map_err(|_| ActivationError::Unavailable)?;
    let r: Request = serde_json::from_slice(body).map_err(|_| ActivationError::Invalid)?;
    if !peer.tenants.contains(&r.tenant) {
        return Err(ActivationError::Refused);
    }
    let cfg = runtime
        .config
        .activation
        .as_ref()
        .ok_or(ActivationError::Unavailable)?;
    let store = runtime
        .activation
        .as_ref()
        .ok_or(ActivationError::Unavailable)?;
    let state = service_transport::authority(
        &runtime.client,
        &runtime.config.server_endpoint,
        &runtime.config.deployment,
        &r.tenant,
    )
    .await
    .map_err(|_| ActivationError::Unavailable)?;
    let p: Policy = serde_json::from_value(
        state["artifact"]["bindings"][format!("stage2:{}", runtime.config.service)].clone(),
    )
    .map_err(|_| ActivationError::Refused)?;
    if p.scope["tenant"] != r.tenant
        || p.scope["deployment"] != runtime.config.deployment
        || peer.service != p.coordinator && !p.readers.contains(&peer.service)
    {
        return Err(ActivationError::Refused);
    }
    store
        .initialize(&p.scope, p.initial_epoch, &p.initial_artifact_set_digest)
        .await?;
    match &r.action {
        Operation::PauseLookup { transition_id } => {
            return store.lookup(&p.scope, transition_id, true).await;
        }
        Operation::ActivationLookup { transition_id } => {
            return store.lookup(&p.scope, transition_id, false).await;
        }
        Operation::ActivationHead => return store.head(&p.scope).await,
        _ => {}
    }
    if peer.service != p.coordinator {
        return Err(ActivationError::Refused);
    }
    if matches!(r.action, Operation::Flush) {
        let cfg = runtime
            .config
            .delivery
            .as_ref()
            .ok_or(ActivationError::Unavailable)?;
        let registration = munarium_gate::activation_delivery::registration(
            &state,
            &p.scope,
            &cfg.server_service,
            &runtime.config.service,
            "gate",
        )?;
        let now = service_transport::now()
            .map_err(|_| ActivationError::Unavailable)?
            .try_into()
            .map_err(|_| ActivationError::Unavailable)?;
        let Some(event) = store.delivery_next(&p.scope, &registration, now).await? else {
            return Ok(json!({"delivered":0}));
        };
        let ack = delivery_service::deliver(runtime, &r.tenant, &event)
            .await
            .map_err(|_| ActivationError::Unavailable)?;
        store.delivery_ack(&p.scope, &event, &ack).await?;
        return Ok(json!({"delivered":1,"acknowledgement":ack}));
    }
    let t = match &r.action {
        Operation::Pause { transition } | Operation::ApplyActivation { transition } => {
            wire::parse(transition)?
        }
        Operation::Resume { completion } => {
            wire::raw(completion)?;
            completion["transition"].clone()
        }
        _ => return Err(ActivationError::Invalid),
    };
    wire::shape(&t, "activation")?;
    wire::scoped(&t, &p.scope)?;
    let id = t["transition"]["id"]
        .as_str()
        .ok_or(ActivationError::Invalid)?;
    let ratified = post(
        runtime,
        &format!(
            "{}/v1/transitions",
            cfg.council_endpoint.trim_end_matches('/')
        ),
        json!({"tenant":r.tenant,"action":{"operation":"lookup","transition_id":id}}),
    )
    .await?;
    let mut evidence = Evidence {
        receipts: Vec::new(),
        heads: Vec::new(),
    };
    if matches!(r.action, Operation::Resume { .. }) {
        for (owner, url) in [
            (
                "registry",
                format!(
                    "{}/v1/activation",
                    runtime.config.registry_endpoint.trim_end_matches('/')
                ),
            ),
            (
                "server",
                format!(
                    "{}/v1/platform/{}/activation",
                    runtime.config.server_endpoint.trim_end_matches('/'),
                    r.tenant
                ),
            ),
            (
                "warden",
                format!(
                    "{}/v1/activation",
                    runtime.config.warden_endpoint.trim_end_matches('/')
                ),
            ),
        ] {
            let receipt = post(
                runtime,
                &url,
                json!({"tenant":r.tenant,"action":{"operation":"lookup","transition_id":id}}),
            )
            .await?;
            wire::check_receipt(&t, &receipt, owner, "applied")?;
            evidence.receipts.push(receipt);
            let head = post(
                runtime,
                &url,
                json!({"tenant":r.tenant,"action":{"operation":"head"}}),
            )
            .await?;
            wire::check_head(&t, &head, owner)?;
            evidence.heads.push(head);
        }
    }
    // A governing revision changed during dependency lookups: do not commit under mixed inputs.
    let current = service_transport::authority(
        &runtime.client,
        &runtime.config.server_endpoint,
        &runtime.config.deployment,
        &r.tenant,
    )
    .await
    .map_err(|_| ActivationError::Unavailable)?;
    if current != state {
        return Err(ActivationError::Refused);
    }
    let auth = Authority {
        scope: p.scope,
        ratified,
        now: service_transport::now()
            .map_err(|_| ActivationError::Unavailable)?
            .try_into()
            .map_err(|_| ActivationError::Unavailable)?,
    };
    match r.action {
        Operation::Pause { .. } => store.pause(&auth, &t).await,
        Operation::ApplyActivation { .. } => store.apply(&auth, &t).await,
        Operation::Resume { completion } => store.resume(&auth, &completion, &evidence).await,
        _ => Err(ActivationError::Invalid),
    }
}
pub(super) async fn operate(
    State(runtime): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Ok(v) = serde_json::from_slice::<Value>(&body)
        && !matches!(
            v["action"]["operation"].as_str(),
            Some(
                "flush"
                    | "pause"
                    | "pause-lookup"
                    | "apply-activation"
                    | "activation-lookup"
                    | "activation-head"
                    | "resume"
            )
        )
    {
        return execution_service::operate(State(runtime), ConnectInfo(peer), body).await;
    }
    admitted(&runtime, &peer, &body)
        .await
        .map(Json)
        .map_err(|e| {
            (
                match e {
                    ActivationError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                    ActivationError::Conflict => StatusCode::CONFLICT,
                    ActivationError::Invalid => StatusCode::BAD_REQUEST,
                    _ => StatusCode::FORBIDDEN,
                },
                Json(json!({"error":e.to_string()})),
            )
        })
}
