// SPDX-License-Identifier: Apache-2.0
//! Opt-in prepared release adapter. All authority is fetched from enrolled owners.
use super::*;
use munarium_gate::{
    action_journal::{Admission, Consumption},
    activation_wire::{self as wire, Error as E},
    final_send::Custody,
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    target_endpoint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    proposer: String,
    request: Value,
    requester_chain: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    scope: Value,
    council: String,
    warden: String,
    connector: String,
    readers: BTreeSet<String>,
    stream: String,
    generation: u64,
    recovery: u64,
    requests: BTreeMap<String, Prepared>,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Action {
    Reconcile {
        operation_id: String,
    },
    Prepare {
        operation_id: String,
        attempt_id: String,
    },
    Source {
        operation_id: String,
        attempt_id: String,
    },
    Claim {
        operation_id: String,
        approval_id: String,
    },
    ClaimLookup {
        operation_id: String,
    },
    Consume {
        operation_id: String,
    },
    FinalSend {
        operation_id: String,
        invocation: Value,
    },
    Unresolved {
        operation_id: String,
    },
    #[serde(rename = "action-flush")]
    Flush,
    Cancel {
        approval: Value,
        approval_revision: u64,
        operation_ref: Value,
        attempt: Value,
        withdrawal_id: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    tenant: String,
    action: Action,
}
async fn post(rt: &Runtime, url: String, body: Value) -> Result<Value, E> {
    if !url.starts_with("https://") {
        return Err(E::Refused);
    }
    let response = rt
        .client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|_| E::Unavailable)?;
    service_transport::json_response(response, 262144)
        .await
        .map_err(|_| E::Unavailable)
}
fn now() -> Result<u64, E> {
    service_transport::now()
        .map_err(|_| E::Unavailable)?
        .try_into()
        .map_err(|_| E::Unavailable)
}
fn source(p: &Policy, operation: &str) -> Result<Value, E> {
    let prepared = p.requests.get(operation).ok_or(E::Refused)?;
    let mut r = prepared.request.clone();
    r["intent_digest"] = json!(wire::digest("intent", &r["intent"])?);
    r["context_digest"] = json!(wire::digest("context", &r["context"])?);
    wire::shape(&r, "action-request")?;
    wire::scoped(&r, &p.scope)?;
    if r["operation"]["id"] != operation
        || r["context"]["mode"] != "enforce"
        || r["intent"]["environment"] != "disposable"
        || r["intent"]["capability_operation"] != "release.publish_approved_artifact"
        || r["intent"]["attachments"] != json!([])
        || r["context"]["recovery"]["revision"] != p.recovery
        || !prepared.requester_chain.contains(&r["intent"]["actor"])
        || !prepared.requester_chain.contains(&r["intent"]["origin"])
    {
        return Err(E::Refused);
    }
    let d = json!({"schema_version":1,"type":"action-decision","profile":"stage2-single-cell-v1",
        "operation":r["operation"],"attempt":r["attempt"],"request_digest":wire::digest("action-request",&r)?,"context_digest":r["context_digest"],
        "outcome":"approval-required","reason_codes":["distinct-human-required"],"obligations":[
          {"kind":"distinct-approval","owner":"council","policy_digest":r["context"]["policy_digest"]},
          {"kind":"mandatory-recording","owner":"server","phase":"before-send"},
          {"kind":"action-capacity","owner":"gate","target":r["intent"]["target"],"limit":2,"window_seconds":3600},
          {"kind":"credential-custody","owner":"warden","audience":r["intent"]["target"]}]});
    wire::shape(&d, "action-decision")?;
    Ok(
        json!({"request":r,"decision":d,"current_context":r["context"],"requester_chain":prepared.requester_chain}),
    )
}
async fn approval(rt: &Runtime, tenant: &str, id: &str) -> Result<Value, E> {
    let cfg = rt.config.activation.as_ref().ok_or(E::Unavailable)?;
    let v = post(
        rt,
        format!(
            "{}/v1/approvals",
            cfg.council_endpoint.trim_end_matches('/')
        ),
        json!({"tenant":tenant,"action":{"operation":"lookup","id":id}}),
    )
    .await?;
    if v["currently_usable"] != true || v["status"] != "approved" || v["revision"] != 1 {
        return Err(E::Refused);
    }
    Ok(v)
}
async fn admission(
    rt: &Runtime,
    p: &Policy,
    tenant: &str,
    operation: &str,
    id: &str,
) -> Result<Admission, E> {
    let s = source(p, operation)?;
    let a = approval(rt, tenant, id).await?;
    Ok(Admission {
        request: s["request"].clone(),
        decision: s["decision"].clone(),
        approval: a["approval"].clone(),
        approval_event: a["audit"]["event"].clone(),
        approval_ack: a["audit"]["acknowledgement"].clone(),
        now: now()?,
    })
}
async fn fresh(rt: &Runtime, tenant: &str, state: &Value) -> Result<(), E> {
    let next = service_transport::authority(
        &rt.client,
        &rt.config.server_endpoint,
        &rt.config.deployment,
        tenant,
    )
    .await
    .map_err(|_| E::Unavailable)?;
    if next != *state {
        return Err(E::Refused);
    }
    Ok(())
}
async fn admitted(rt: &Runtime, peer: &Peer, body: &[u8]) -> Result<Value, E> {
    let _permit = rt
        .activation_permits
        .try_acquire()
        .map_err(|_| E::Unavailable)?;
    let input: Input = serde_json::from_slice(body).map_err(|_| E::Invalid)?;
    let tenant = &input.tenant;
    if !peer.tenants.contains(tenant) {
        return Err(E::Refused);
    }
    let state = service_transport::authority(
        &rt.client,
        &rt.config.server_endpoint,
        &rt.config.deployment,
        tenant,
    )
    .await
    .map_err(|_| E::Unavailable)?;
    let p: Policy = serde_json::from_value(
        state["artifact"]["bindings"][format!("execution:{}", rt.config.service)].clone(),
    )
    .map_err(|_| E::Refused)?;
    if p.scope["tenant"] != *tenant || p.scope["deployment"] != rt.config.deployment {
        return Err(E::Refused);
    }
    let store = rt.activation.as_ref().ok_or(E::Unavailable)?;
    let privileged = peer.service == p.council
        || peer.service == p.warden
        || peer.service == p.connector
        || p.readers.contains(&peer.service);
    if !privileged && !p.requests.values().any(|r| r.proposer == peer.service) {
        return Err(E::Refused);
    }
    // Changed external recovery generation cannot initialize over an older enrolled store.
    if matches!(
        input.action,
        Action::Prepare { .. }
            | Action::Claim { .. }
            | Action::Consume { .. }
            | Action::FinalSend { .. }
    ) {
        store.execution_generation(&p.scope, p.recovery).await?;
    }
    store
        .action_enroll(&p.scope, &p.stream, p.generation)
        .await?;
    match input.action {
        Action::Reconcile { operation_id } => {
            if !p.readers.contains(&peer.service) {
                return Err(E::Refused);
            }
            let cfg = rt.config.execution.as_ref().ok_or(E::Unavailable)?;
            let observation = post(
                rt,
                format!("{}/observe", cfg.target_endpoint.trim_end_matches('/')),
                json!({}),
            )
            .await?;
            let receipt = observation["effects"]
                .as_array()
                .ok_or(E::Invalid)?
                .iter()
                .find(|r| {
                    r["operation"]["scope"] == p.scope && r["operation"]["id"] == operation_id
                })
                .ok_or(E::Refused)?;
            store
                .action_reconcile(&p.scope, &operation_id, receipt, now()?)
                .await
        }
        Action::Prepare {
            operation_id,
            attempt_id,
        }
        | Action::Source {
            operation_id,
            attempt_id,
        } => {
            let prepare = serde_json::from_slice::<Value>(body).map_err(|_| E::Invalid)?["action"]
                ["operation"]
                == "prepare";
            let entry = p.requests.get(&operation_id).ok_or(E::Refused)?;
            if (prepare && peer.service != entry.proposer) || (!prepare && !privileged) {
                return Err(E::Refused);
            }
            let s = source(&p, &operation_id)?;
            if s["request"]["attempt"]["id"] != attempt_id {
                return Err(E::Refused);
            }
            let head = store.head(&p.scope).await?;
            if head["paused"] != false
                || head["epoch"] != s["request"]["context"]["activation"]["revision"]
                || head["artifact_set_digest"]
                    != munarium_gate::action_journal::artifact_set_for_service(&s["request"])?
            {
                return Err(E::Refused);
            }
            if prepare {
                let chain = rt
                    .assertion(
                        tenant,
                        &rt.config.server_service,
                        &["propose"],
                        format!("action-records:{tenant}"),
                    )
                    .await
                    .map_err(|_| E::Unavailable)?;
                for key in ["request", "decision"] {
                    rt.records(
                        tenant,
                        &chain,
                        json!({"operation":"action-archive","record":wire::raw(&s[key])?}),
                    )
                    .await
                    .map_err(|_| E::Unavailable)?;
                }
            }
            fresh(rt, tenant, &state).await?;
            store.action_source(&p.scope, &s, prepare).await
        }
        Action::Claim {
            operation_id,
            approval_id,
        } => {
            if peer.service != p.connector {
                return Err(E::Refused);
            }
            let a = admission(rt, &p, tenant, &operation_id, &approval_id).await?;
            fresh(rt, tenant, &state).await?;
            store.action_claim(&a).await
        }
        Action::ClaimLookup { operation_id } => {
            if !privileged {
                return Err(E::Refused);
            }
            let mut result = store.action_lookup(&p.scope, &operation_id).await?;
            result["claim_audit"] = store.action_evidence(&p.scope, &result["claim"]).await?;
            if !result["consumption"].is_null() {
                result["predispatch_audit"] = store
                    .action_evidence(&p.scope, &result["consumption"]["predispatch"])
                    .await?;
            }
            result["dispatch"] = store.action_dispatch(&p.scope, &operation_id).await?;
            Ok(result)
        }
        Action::Consume { operation_id } => {
            if peer.service != p.connector {
                return Err(E::Refused);
            }
            let old = store.action_lookup(&p.scope, &operation_id).await?;
            let id = old["binding"]["approval"]["approval"]["id"]
                .as_str()
                .ok_or(E::Invalid)?;
            let mut a = admission(rt, &p, tenant, &operation_id, id).await?;
            let g = post(
                rt,
                format!(
                    "{}/v1/grants",
                    rt.config.warden_endpoint.trim_end_matches('/')
                ),
                json!({"tenant":tenant,"action":{"operation":"issue","operation_id":operation_id}}),
            )
            .await?;
            fresh(rt, tenant, &state).await?;
            a.now = now()?;
            store
                .action_consume(
                    &a,
                    &Consumption {
                        grant_event: g["event"].clone(),
                        grant_ack: g["acknowledgement"].clone(),
                        worker: p.connector,
                        limits: BTreeMap::new(),
                        now: a.now,
                    },
                )
                .await
        }
        Action::FinalSend {
            operation_id,
            invocation,
        } => {
            if peer.service != p.connector {
                return Err(E::Refused);
            }
            let old = store.action_lookup(&p.scope, &operation_id).await?;
            let id = old["binding"]["approval"]["approval"]["id"]
                .as_str()
                .ok_or(E::Invalid)?;
            let mut a = admission(rt, &p, tenant, &operation_id, id).await?;
            let c=post(rt,format!("{}/v1/grants",rt.config.warden_endpoint.trim_end_matches('/')),json!({"tenant":tenant,"action":{"operation":"validate","operation_id":operation_id,"invocation":invocation}})).await?;
            if c["connector"] != peer.service || c["invocation"] != invocation {
                return Err(E::Refused);
            }
            fresh(rt, tenant, &state).await?;
            a.now = now()?;
            store
                .action_final(
                    &a,
                    &Custody {
                        grant: c["grant"].clone(),
                        invocation,
                        worker: peer.service.clone(),
                        fence: c["fence"].as_u64().ok_or(E::Invalid)?,
                        expires_at: c["expires_at"].as_u64().ok_or(E::Invalid)?,
                        recovery: p.recovery,
                    },
                )
                .await
        }
        Action::Unresolved { operation_id } => {
            if peer.service != p.connector && !p.readers.contains(&peer.service) {
                return Err(E::Refused);
            }
            store
                .action_unresolved(&p.scope, &operation_id, now()?)
                .await
        }
        Action::Flush => {
            if !privileged {
                return Err(E::Refused);
            }
            let Some(event) = store.action_pending(&p.scope).await? else {
                return Ok(json!({"delivered":0}));
            };
            let ack = delivery_service::deliver(rt, tenant, &event)
                .await
                .map_err(|_| E::Unavailable)?;
            store.action_ack(&p.scope, &event, &ack).await?;
            Ok(json!({"delivered":1,"acknowledgement":ack}))
        }
        Action::Cancel {
            approval,
            approval_revision,
            operation_ref,
            attempt,
            withdrawal_id,
        } => {
            if peer.service != p.council || approval_revision != 1 {
                return Err(E::Refused);
            }
            wire::scoped(&operation_ref, &p.scope)?;
            wire::scoped(&attempt, &p.scope)?;
            let receipt = store
                .action_cancel(
                    &p.scope,
                    operation_ref["id"].as_str().ok_or(E::Invalid)?,
                    attempt["id"].as_str().ok_or(E::Invalid)?,
                    &approval,
                    &withdrawal_id,
                )
                .await?;
            Ok(
                json!({"approval":approval,"approval_revision":approval_revision,"operation":operation_ref,"attempt":attempt,"withdrawal_id":withdrawal_id,"status":receipt["status"]}),
            )
        }
    }
}
pub(super) async fn operate(
    State(rt): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admitted(&rt, &peer, &body).await.map(Json).map_err(|e| {
        (
            match e {
                E::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                E::Conflict => StatusCode::CONFLICT,
                E::Invalid => StatusCode::BAD_REQUEST,
                _ => StatusCode::FORBIDDEN,
            },
            Json(json!({"error":e.to_string()})),
        )
    })
}
