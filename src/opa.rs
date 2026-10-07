// SPDX-License-Identifier: Apache-2.0
//! Pinned OPA worker adapter. The supervising worker enforces process bounds.
use crate::decision::{Engine, Error};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

/// Operator configuration; never populated from an agent request.
pub struct Opa {
    /// Trusted Python interpreter.
    pub python: PathBuf,
    /// This repository's bounded worker script.
    pub worker: PathBuf,
    /// Pinned native OPA executable.
    pub executable: PathBuf,
    /// SHA-256 of the worker source, with the `sha256:` prefix.
    pub worker_digest: String,
    /// SHA-256 of the native executable, with the `sha256:` prefix.
    pub executable_digest: String,
    /// Exact admitted engine version.
    pub version: String,
    /// Admitted capabilities JSON, with no network, clock, random or runtime access.
    pub capabilities: Value,
}
fn hash(path: &std::path::Path) -> Result<String, Error> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(path).map_err(|_| Error::Evaluator)?)
    ))
}
impl Engine for Opa {
    fn name(&self) -> &'static str {
        "opa"
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn digest(&self) -> &str {
        &self.executable_digest
    }
    fn evaluate(&mut self, policy: &Value, input: &Value) -> Result<Value, Error> {
        if hash(&self.executable)? != self.executable_digest
            || hash(&self.worker)? != self.worker_digest
            || policy["worker_digest"] != self.worker_digest
            || policy["capabilities_digest"]
                != crate::decision::digest(
                    "munarium:opa-capabilities:v1",
                    &serde_json::to_vec(&self.capabilities).map_err(|_| Error::Evaluator)?,
                )
        {
            return Err(Error::Evaluator);
        }
        let request = json!({"executable":self.executable,"digest":self.executable_digest,"policy":policy["code"],"input":input,"capabilities":self.capabilities});
        let mut child = Command::new(&self.python)
            .arg(&self.worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Evaluator)?;
        let raw = serde_json::to_vec(&request).map_err(|_| Error::Evaluator)?;
        if child
            .stdin
            .take()
            .ok_or(Error::Evaluator)?
            .write_all(&raw)
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Evaluator);
        }
        let output = child.wait_with_output().map_err(|_| Error::Evaluator)?;
        if !output.status.success() || output.stdout.len() > 65536 {
            return Err(Error::Evaluator);
        }
        let result: Value = serde_json::from_slice(&output.stdout).map_err(|_| Error::Evaluator)?;
        let rows = result["result"].as_array().ok_or(Error::Evaluator)?;
        if rows.len() != 1 || result.get("errors").is_some() {
            return Err(Error::Evaluator);
        }
        let expressions = rows[0]["expressions"].as_array().ok_or(Error::Evaluator)?;
        if expressions.len() != 1 {
            return Err(Error::Evaluator);
        }
        expressions[0].get("value").cloned().ok_or(Error::Evaluator)
    }
}
