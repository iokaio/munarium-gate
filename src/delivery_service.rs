// SPDX-License-Identifier: Apache-2.0
//! Bounded owner-authenticated delivery; no caller can supply evidence or credentials.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub server_service: String,
    pub warden_endpoint: String,
    pub provider_id: String,
    pub provider_token_file: PathBuf,
}
pub(super) async fn deliver(
    runtime: &Runtime,
    tenant: &str,
    event: &Value,
) -> Result<Value, Failure> {
    let cfg = runtime
        .config
        .delivery
        .as_ref()
        .ok_or(Failure::Unavailable)?;
    let endpoint = reqwest::Url::parse(&cfg.warden_endpoint).map_err(|_| Failure::Configuration)?;
    if endpoint.scheme() != "https"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || !cfg.provider_token_file.is_absolute()
    {
        return Err(Failure::Configuration);
    }
    let token =
        std::fs::read_to_string(&cfg.provider_token_file).map_err(|_| Failure::Configuration)?;
    if token.len() > 65536 {
        return Err(Failure::Configuration);
    }
    let response = runtime.client.post(format!("{}/v1/identity",cfg.warden_endpoint.trim_end_matches('/')))
        .json(&json!({"tenant":tenant,"audience":cfg.server_service,"action":{"operation":"root","provider_id":cfg.provider_id,"token":token.trim(),"scopes":["propose"],"resources":[format!("action-records:{tenant}")]}}))
        .send().await.map_err(|_| Failure::Unavailable)?;
    let identity = service_transport::json_response(response, 65536).await?;
    let usable = identity["usable_at"].as_i64().ok_or(Failure::Refused)?;
    let now = service_transport::now()?;
    if usable > now + 3 {
        return Err(Failure::Refused);
    }
    if usable >= now {
        tokio::time::sleep(std::time::Duration::from_secs((usable - now + 1) as u64)).await;
    }
    let chain: Vec<String> =
        serde_json::from_value(identity["chain"].clone()).map_err(|_| Failure::Refused)?;
    let response = runtime.client.post(format!("{}/v1/platform/{tenant}/records",runtime.config.server_endpoint.trim_end_matches('/')))
        .json(&json!({"chain":chain,"action":{"operation":"action-append","event":serde_json::to_string(event).map_err(|_| Failure::Refused)?}}))
        .send().await.map_err(|_| Failure::Unavailable)?;
    service_transport::json_response(response, 65536).await
}
