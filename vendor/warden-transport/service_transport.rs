// SPDX-License-Identifier: Apache-2.0
//! Direct mTLS with enrolled certificate peers and bounded HTTPS authority reads.
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, rustls, server::TlsStream};

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub service: String,
    pub tenants: BTreeSet<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub listen: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub ca_file: PathBuf,
    pub peers: BTreeMap<String, Peer>,
}
#[derive(Debug)]
pub enum Failure {
    Configuration,
    Unavailable,
    Refused,
}
pub struct Mtls {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    peers: Arc<BTreeMap<String, Peer>>,
    handshakes: tokio::task::JoinSet<Option<(TlsStream<TcpStream>, Peer)>>,
}
impl Mtls {
    pub async fn bind(config: &TlsConfig) -> Result<Self, Failure> {
        if config.peers.is_empty()
            || config.peers.iter().any(|(pin, peer)| {
                pin.len() != 64
                    || !pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || peer.service.is_empty()
                    || peer.tenants.is_empty()
            })
        {
            return Err(Failure::Configuration);
        }
        let cert = std::fs::read(&config.certificate_file).map_err(|_| Failure::Configuration)?;
        let key = std::fs::read(&config.private_key_file).map_err(|_| Failure::Configuration)?;
        let ca = std::fs::read(&config.ca_file).map_err(|_| Failure::Configuration)?;
        let certificates = rustls_pemfile::certs(&mut &cert[..])
            .collect::<io::Result<Vec<_>>>()
            .map_err(|_| Failure::Configuration)?;
        let key = rustls_pemfile::private_key(&mut &key[..])
            .map_err(|_| Failure::Configuration)?
            .ok_or(Failure::Configuration)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca[..]) {
            roots
                .add(cert.map_err(|_| Failure::Configuration)?)
                .map_err(|_| Failure::Configuration)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(|_| Failure::Configuration)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Failure::Configuration)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .map_err(|_| Failure::Configuration)?;
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let listener = TcpListener::bind(&config.listen)
            .await
            .map_err(|_| Failure::Configuration)?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            peers: Arc::new(config.peers.clone()),
            handshakes: tokio::task::JoinSet::new(),
        })
    }
}
impl Listener for Mtls {
    type Io = TlsStream<TcpStream>;
    type Addr = Peer;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                connection=self.listener.accept(),if self.handshakes.len()<64=>{
                    match connection {
                        Ok((stream,_))=>{
                            let tls=self.acceptor.clone();let peers=self.peers.clone();
                            self.handshakes.spawn(async move {
                                let stream=tokio::time::timeout(Duration::from_secs(5),tls.accept(stream)).await.ok()?.ok()?;
                                let leaf=stream.get_ref().1.peer_certificates()?.first()?;
                                let pin=format!("{:x}",Sha256::digest(leaf.as_ref()));
                                Some((stream,peers.get(&pin)?.clone()))
                            });
                        }
                        Err(_)=>tokio::time::sleep(Duration::from_millis(100)).await,
                    }
                }
                result=self.handshakes.join_next(),if !self.handshakes.is_empty()=>{
                    if let Some(Ok(Some(connection)))=result { return connection; }
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<Peer> {
        self.listener.local_addr()?;
        Ok(Peer {
            service: String::new(),
            tenants: BTreeSet::new(),
        })
    }
}
impl Connected<IncomingStream<'_, Mtls>> for Peer {
    fn connect_info(stream: IncomingStream<'_, Mtls>) -> Self {
        stream.remote_addr().clone()
    }
}

pub fn client(config: &TlsConfig) -> Result<reqwest::Client, Failure> {
    let mut identity =
        std::fs::read(&config.private_key_file).map_err(|_| Failure::Configuration)?;
    identity.push(b'\n');
    identity.extend(std::fs::read(&config.certificate_file).map_err(|_| Failure::Configuration)?);
    let identity = reqwest::Identity::from_pem(&identity).map_err(|_| Failure::Configuration)?;
    let ca = std::fs::read(&config.ca_file).map_err(|_| Failure::Configuration)?;
    let ca = reqwest::Certificate::from_pem(&ca).map_err(|_| Failure::Configuration)?;
    reqwest::Client::builder()
        .identity(identity)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| Failure::Configuration)
}
pub async fn json_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Value, Failure> {
    if !response.status().is_success() {
        return Err(Failure::Refused);
    }
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Vec::new();
    while let Some(part) = response.chunk().await.map_err(|_| Failure::Unavailable)? {
        if bytes.len() + part.len() > limit {
            return Err(Failure::Unavailable);
        }
        bytes.extend(part);
    }
    serde_json::from_slice(&bytes).map_err(|_| Failure::Unavailable)
}
pub async fn authority(
    client: &reqwest::Client,
    endpoint: &str,
    deployment: &str,
    tenant: &str,
) -> Result<Value, Failure> {
    if tenant.is_empty()
        || tenant.len() > 128
        || !tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err(Failure::Refused);
    }
    let response = client
        .get(format!(
            "{}/v1/platform/{tenant}/authority",
            endpoint.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    // Any failure of our enrolled authority hop is dependency unavailability,
    // not a refusal attributed to the downstream caller.
    let state = json_response(response, 1048576)
        .await
        .map_err(|_| Failure::Unavailable)?;
    if state["config"]["deployment"] != deployment
        || state["config"]["tenant"] != tenant
        || state["head"].as_u64().is_none_or(|h| h == 0)
        || !state["artifact"]["bindings"].is_object()
    {
        return Err(Failure::Unavailable);
    }
    Ok(state)
}
pub fn now() -> Result<i64, Failure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Failure::Unavailable)?
        .as_secs()
        .try_into()
        .map_err(|_| Failure::Unavailable)
}
