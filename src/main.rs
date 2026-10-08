// SPDX-License-Identifier: Apache-2.0
//! Decision service with authenticated dependencies and durable, resumable recording.
mod activation_service;
mod decision_store;
mod delivery_service;
#[path = "../vendor/warden-transport/service_transport.rs"]
mod service_transport;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use munarium_gate::{
    decision::{self, Error, Host, Principal, Receipt, Snapshot},
    opa::Opa,
    policy, principal,
};
use serde::Deserialize;
use serde_json::{Value, json};
use service_transport::{Failure, Peer, TlsConfig};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evaluator {
    python: PathBuf,
    worker: PathBuf,
    executable: PathBuf,
    worker_digest: String,
    executable_digest: String,
    version: String,
    capabilities: Value,
}
impl Evaluator {
    fn engine(&self) -> Opa {
        Opa {
            python: self.python.clone(),
            worker: self.worker.clone(),
            executable: self.executable.clone(),
            worker_digest: self.worker_digest.clone(),
            executable_digest: self.executable_digest.clone(),
            version: self.version.clone(),
            capabilities: self.capabilities.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    delivery: Option<delivery_service::Config>,
    tls: TlsConfig,
    server_endpoint: String,
    registry_endpoint: String,
    warden_endpoint: String,
    deployment: String,
    service: String,
    server_service: String,
    registry_service: String,
    provider_id: String,
    provider_token_file: PathBuf,
    journal: PathBuf,
    evaluator: Evaluator,
    activation: Option<activation_service::Config>,
}
struct Runtime {
    config: Config,
    client: reqwest::Client,
    journal: Mutex<decision_store::Store>,
    serial: tokio::sync::Mutex<()>,
    activation: Option<munarium_gate::activation::Store>,
    activation_permits: tokio::sync::Semaphore,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Submit { request: String },
    Lookup { operation_id: String },
    Replay { operation_id: String },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant: String,
    chain: Vec<String>,
    action: Operation,
}
fn encoded(value: &Value) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::Request)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value[key].as_str().ok_or(Error::Request)
}
fn map_failure(_: Failure) -> Error {
    Error::Recording
}

impl Runtime {
    async fn assertion(
        &self,
        tenant: &str,
        audience: &str,
        scopes: &[&str],
        resource: String,
    ) -> Result<Vec<String>, Error> {
        let token = std::fs::read_to_string(&self.config.provider_token_file)
            .map_err(|_| Error::Identity)?;
        if token.len() > 65536 {
            return Err(Error::Identity);
        }
        let response=self.client.post(format!("{}/v1/identity",self.config.warden_endpoint.trim_end_matches('/')))
            .json(&json!({"tenant":tenant,"audience":audience,"action":{"operation":"root","provider_id":self.config.provider_id,
                "token":token.trim(),"scopes":scopes,"resources":[resource]}})).send().await.map_err(|_|Error::Identity)?;
        let response = service_transport::json_response(response, 65536)
            .await
            .map_err(|_| Error::Identity)?;
        let usable = response["usable_at"].as_i64().ok_or(Error::Identity)?;
        let now = service_transport::now().map_err(|_| Error::Identity)?;
        if usable > now + 3 {
            return Err(Error::Identity);
        }
        if usable >= now {
            tokio::time::sleep(Duration::from_secs((usable - now + 1) as u64)).await;
        }
        serde_json::from_value(response["chain"].clone()).map_err(|_| Error::Identity)
    }
    async fn records(&self, tenant: &str, chain: &[String], action: Value) -> Result<Value, Error> {
        let response = self
            .client
            .post(format!(
                "{}/v1/platform/{tenant}/records",
                self.config.server_endpoint.trim_end_matches('/')
            ))
            .json(&json!({"chain":chain,"action":action}))
            .send()
            .await
            .map_err(|_| Error::Recording)?;
        service_transport::json_response(response, 16 * 1024 * 1024 + 131072)
            .await
            .map_err(map_failure)
    }
    async fn archived(
        &self,
        tenant: &str,
        operation: &str,
        chain: &[String],
    ) -> Result<Option<Receipt>, Error> {
        let archived = self
            .records(
                tenant,
                chain,
                json!({"operation":"replay","operation_id":operation}),
            )
            .await?;
        if archived["bundle"].is_null() && archived["digest"].is_null() {
            return Ok(None);
        }
        Receipt::restore(
            text(&archived, "bundle")?.as_bytes(),
            text(&archived, "digest")?,
        )
        .map(Some)
    }
    async fn deliver(
        &self,
        tenant: &str,
        operation: &str,
        chain: &[String],
        receipt: &[u8],
        events: &[String],
    ) -> Result<(), Error> {
        for raw in events {
            let event = decision::parse(raw.as_bytes())?;
            let ack = self
                .records(tenant, chain, json!({"operation":"append","event":raw}))
                .await?;
            if ack["schema_version"] != 1
                || ack["tenant"] != event["tenant"]
                || ack["event_id"] != event["event_id"]
                || ack["payload_digest"] != event["payload_digest"]
                || ack["event_digest"]
                    != decision::digest("munarium:decision-event:v1", raw.as_bytes())
                || ack["ledger_id"].as_str().is_none_or(str::is_empty)
                || ack["ledger_position"].as_u64().is_none_or(|n| n == 0)
            {
                return Err(Error::Recording);
            }
        }
        let bundle = std::str::from_utf8(receipt).map_err(|_| Error::Recording)?;
        let ack = self
            .records(
                tenant,
                chain,
                json!({"operation":"archive","bundle":bundle}),
            )
            .await?;
        if ack["digest"] != decision::digest("munarium:decision-replay:v1", receipt) {
            return Err(Error::Recording);
        }
        self.journal
            .lock()
            .map_err(|_| Error::Recording)?
            .complete(tenant, operation)
    }
}
struct RemoteHost {
    runtime: Arc<Runtime>,
    handle: tokio::runtime::Handle,
    trust: principal::Trust,
    authority: Value,
    server_chain: Vec<String>,
    registry_chain: Vec<String>,
}
impl Host for RemoteHost {
    fn principal(&mut self, chain: &[String]) -> Result<Principal, Error> {
        self.trust.now = service_transport::now().map_err(|_| Error::Identity)?;
        let p = principal::verify(chain, &self.trust).map_err(|_| Error::Identity)?;
        Ok(Principal {
            tenant: p.tenant().into(),
            origin: p.origin().into(),
            actor: p.actor().into(),
            origin_kind: p.origin_kind().into(),
            digest: p.fingerprint().into(),
            scopes: p.scopes().to_vec(),
            resources: p.resources().to_vec(),
        })
    }
    fn snapshot(&mut self, tenant: &str, request: &Value) -> Result<Snapshot, Error> {
        let admitted =
            &self.authority["artifact"]["bindings"]["decisions"][text(request, "target_id")?];
        let mut snapshot: Snapshot =
            serde_json::from_value(admitted.clone()).map_err(|_| Error::Manifest)?;
        let response=self.handle.block_on(async {
            let response=self.runtime.client.post(format!("{}/v1/candidates",self.runtime.config.registry_endpoint.trim_end_matches('/')))
                .json(&json!({"tenant":tenant,"chain":self.registry_chain,"action":{"operation":"resolve", "manifest_digest":request["manifest_digest"],"artifact_digest":snapshot.artifact_digest}}))
                .send().await.map_err(|_|Error::Manifest)?;
            service_transport::json_response(response,262144).await.map_err(|_|Error::Manifest)
        })?;
        if response["status"] != "candidate"
            || response["active"] != false
            || response["artifact_digest"] != snapshot.artifact_digest
            || response["manifest_digest"] != request["manifest_digest"]
        {
            return Err(Error::Manifest);
        }
        snapshot.manifest = response["manifest"].clone();
        for evidence in &mut snapshot.evidence {
            let source = decision::parse(&evidence.source).map_err(|_| Error::Lineage)?;
            if evidence.lineage["derivation_id"] != "test-result"
                || evidence.lineage["derivation_version"] != "1"
                || evidence.lineage["field_path"] != "tests.passed"
                || source["artifact_digest"] != request["parameters"]["artifact_digest"]
                || !source["tests.passed"].is_boolean()
            {
                return Err(Error::Lineage);
            }
            evidence.value = source["tests.passed"].clone();
        }
        Ok(snapshot)
    }
    fn record(&mut self, request: &Value, decision: &Value, replay: &[u8]) -> Result<(), Error> {
        let tenant = text(request, "tenant")?;
        let operation = text(request, "operation_id")?;
        let current = self
            .handle
            .block_on(service_transport::authority(
                &self.runtime.client,
                &self.runtime.config.server_endpoint,
                &self.runtime.config.deployment,
                tenant,
            ))
            .map_err(map_failure)?;
        if current != self.authority {
            return Err(Error::Recording);
        }
        let head = self.handle.block_on(self.runtime.records(
            tenant,
            &self.server_chain,
            json!({"operation":"source-head"}),
        ))?;
        let mut sequence = head["sequence"].as_u64().ok_or(Error::Recording)?;
        let mut prior = head["event_digest"].clone();
        let mut events = Vec::new();
        for (kind, payload) in [
            ("proposal", request),
            (
                if decision.get("outcome").is_some() {
                    "decision"
                } else {
                    "refusal"
                },
                decision,
            ),
        ] {
            sequence = sequence.checked_add(1).ok_or(Error::Recording)?;
            let event = json!({"schema_version":1,"convention":"decision-events-v1","tenant":tenant,"source_service":self.runtime.config.service,
                "source_epoch":self.authority["config"]["epoch"],"event_id":decision::digest("munarium:gate-event-id:v1",format!("{tenant}\0{operation}\0{kind}").as_bytes()),"sequence":sequence,"prior_event_digest":prior,
                "operation_id":operation,"request_digest":decision::digest("munarium:decision-request:v1",&encoded(request)?),"kind":kind,
                "recorded_at":service_transport::now().map_err(|_|Error::Recording)?,"payload_digest":decision::digest("munarium:decision-event-payload:v1",&encoded(payload)?),
                "causation":[],"correlation":[],"payload":payload});
            let raw = encoded(&event)?;
            prior = json!(decision::digest("munarium:decision-event:v1", &raw));
            events.push(String::from_utf8(raw).map_err(|_| Error::Recording)?);
        }
        self.runtime
            .journal
            .lock()
            .map_err(|_| Error::Recording)?
            .prepare(tenant, operation, &encoded(request)?, replay, &events)?;
        self.handle.block_on(self.runtime.deliver(
            tenant,
            operation,
            &self.server_chain,
            replay,
            &events,
        ))
    }
}
async fn operate(
    State(runtime): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    async fn admitted(runtime: Arc<Runtime>, peer: Peer, body: Bytes) -> Result<Value, Error> {
        // One process owns the journal and serializes source sequence allocation/recovery.
        let _serial = runtime.serial.try_lock().map_err(|_| Error::Recording)?;
        let request: Request = serde_json::from_slice(&body).map_err(|_| Error::Request)?;
        if !peer.tenants.contains(&request.tenant) {
            return Err(Error::Identity);
        }
        let authority = service_transport::authority(
            &runtime.client,
            &runtime.config.server_endpoint,
            &runtime.config.deployment,
            &request.tenant,
        )
        .await
        .map_err(map_failure)?;
        let trust = policy::current(
            &authority["artifact"]["bindings"][format!("identity:{}", runtime.config.service)],
            &runtime.config.deployment,
            &request.tenant,
            &runtime.config.service,
            &peer.service,
            service_transport::now().map_err(|_| Error::Identity)?,
        )
        .map_err(|_| Error::Identity)?;
        let caller = principal::verify(&request.chain, &trust).map_err(|_| Error::Identity)?;
        let server_chain = runtime
            .assertion(
                &request.tenant,
                &runtime.config.server_service,
                &["read", "propose"],
                format!("records:{}", request.tenant),
            )
            .await?;
        let operation = match &request.action {
            Operation::Submit { request } => {
                let proposal = decision::parse(request.as_bytes())?;
                decision::validate_record("request", &proposal)?;
                if proposal["tenant"] != caller.tenant()
                    || !caller.permits("evaluate", text(&proposal, "target_id")?)
                {
                    return Err(Error::Identity);
                }
                text(&proposal, "operation_id")?.to_owned()
            }
            Operation::Lookup { operation_id } | Operation::Replay { operation_id } => {
                operation_id.clone()
            }
        };
        let stored = runtime
            .journal
            .lock()
            .map_err(|_| Error::Recording)?
            .lookup(&request.tenant, &operation)?;
        if let Some(stored) = stored {
            let receipt = Receipt::restore(
                &stored.receipt,
                &decision::digest("munarium:decision-replay:v1", &stored.receipt),
            )?;
            if !receipt.belongs_to(caller.origin(), caller.actor(), caller.origin_kind())
                || !caller.permits(
                    if matches!(&request.action, Operation::Submit { .. }) {
                        "evaluate"
                    } else {
                        "read"
                    },
                    text(receipt.request(), "target_id")?,
                )
            {
                return Err(Error::Identity);
            }
            match &request.action {
                Operation::Submit { request: raw } => {
                    if encoded(receipt.request())? != raw.as_bytes() {
                        return Err(Error::Conflict);
                    }
                    if !stored.complete {
                        runtime
                            .deliver(
                                &request.tenant,
                                &operation,
                                &server_chain,
                                &stored.receipt,
                                &stored.events,
                            )
                            .await?;
                    }
                }
                Operation::Lookup { .. } | Operation::Replay { .. } => {}
            }
            let remote = runtime
                .archived(&request.tenant, &operation, &server_chain)
                .await?
                .ok_or(Error::Recording)?;
            if remote.export()? != stored.receipt {
                return Err(Error::Recording);
            }
            if matches!(request.action, Operation::Replay { .. }) {
                let mut engine = runtime.config.evaluator.engine();
                return tokio::task::spawn_blocking(move || remote.replay(&mut engine))
                    .await
                    .map_err(|_| Error::Evaluator)?;
            }
            return Ok(remote.decision().clone());
        }
        // A restored local journal must not cause a second evaluation of an archived operation.
        if let Some(remote) = runtime
            .archived(&request.tenant, &operation, &server_chain)
            .await?
        {
            if !remote.belongs_to(caller.origin(), caller.actor(), caller.origin_kind()) {
                return Err(Error::Identity);
            }
            let scope = if matches!(&request.action, Operation::Submit { .. }) {
                "evaluate"
            } else {
                "read"
            };
            if !caller.permits(scope, text(remote.request(), "target_id")?) {
                return Err(Error::Identity);
            }
            if let Operation::Submit { request: raw } = &request.action
                && encoded(remote.request())? != raw.as_bytes()
            {
                return Err(Error::Conflict);
            }
            if matches!(&request.action, Operation::Replay { .. }) {
                let mut engine = runtime.config.evaluator.engine();
                return tokio::task::spawn_blocking(move || remote.replay(&mut engine))
                    .await
                    .map_err(|_| Error::Evaluator)?;
            }
            return Ok(remote.decision().clone());
        }
        let Operation::Submit { request: raw } = request.action else {
            return Err(Error::Recording);
        };
        if runtime
            .journal
            .lock()
            .map_err(|_| Error::Recording)?
            .pending()?
        {
            return Err(Error::Recording);
        }
        let registry_chain = runtime
            .assertion(
                &request.tenant,
                &runtime.config.registry_service,
                &["read"],
                format!("registry:{}", request.tenant),
            )
            .await?;
        let mut engine = runtime.config.evaluator.engine();
        let mut host = RemoteHost {
            runtime: runtime.clone(),
            handle: tokio::runtime::Handle::current(),
            trust,
            authority,
            server_chain,
            registry_chain,
        };
        tokio::task::spawn_blocking(move || {
            decision::decide(raw.as_bytes(), &request.chain, &mut host, &mut engine)
                .map(|r| r.decision().clone())
        })
        .await
        .map_err(|_| Error::Recording)?
    }
    admitted(runtime, peer, body)
        .await
        .map(Json)
        .map_err(|error| {
            let status = match error {
                Error::Recording => StatusCode::SERVICE_UNAVAILABLE,
                Error::Conflict => StatusCode::CONFLICT,
                Error::Request => StatusCode::BAD_REQUEST,
                _ => StatusCode::FORBIDDEN,
            };
            (status, Json(json!({"error":error.code()})))
        })
}
async fn run() -> Result<(), Failure> {
    let path = std::env::args_os().nth(1).ok_or(Failure::Configuration)?;
    let raw = std::fs::read(path).map_err(|_| Failure::Configuration)?;
    if raw.len() > 1048576 {
        return Err(Failure::Configuration);
    }
    let config: Config = serde_json::from_slice(&raw).map_err(|_| Failure::Configuration)?;
    if !config.journal.is_absolute() {
        return Err(Failure::Configuration);
    }
    let journal =
        decision_store::Store::open(&config.journal).map_err(|_| Failure::Configuration)?;
    let client = service_transport::client(&config.tls)?;
    let activation = activation_service::open(&config.activation).await?;
    let listener = service_transport::Mtls::bind(&config.tls).await?;
    let runtime = Arc::new(Runtime {
        config,
        client,
        journal: Mutex::new(journal),
        serial: tokio::sync::Mutex::new(()),
        activation,
        activation_permits: tokio::sync::Semaphore::new(32),
    });
    let router = Router::new()
        .route("/v1/decisions", post(operate))
        .route("/v1/actions", post(activation_service::operate))
        .layer(DefaultBodyLimit::max(262144))
        .with_state(runtime);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|_| Failure::Unavailable)
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Gate service unavailable: {error:?}");
        std::process::exit(1);
    }
}
