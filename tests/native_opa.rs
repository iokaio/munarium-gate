// SPDX-License-Identifier: Apache-2.0
//! Explicit native-worker integration; ordinary portable tests do not claim Linux bounds.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the pinned Linux OPA and delegated cgroup v2"]
fn linux_worker_through_rust_adapter() {
    use munarium_gate::{
        decision::{Engine, Error, digest},
        opa::Opa,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{path::PathBuf, process::Command};
    let executable = PathBuf::from(std::env::var("OPA_LINUX_EXECUTABLE").unwrap());
    let worker = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/opa_worker_linux.py");
    let python = PathBuf::from("python3");
    let raw = Command::new(&python).args(["-c", "import json,sys; sys.path.insert(0,'scripts'); from check_opa import capabilities; print(json.dumps(capabilities(sys.argv[1])))"])
        .arg(&executable).output().unwrap();
    assert!(raw.status.success());
    let caps: Value = serde_json::from_slice(&raw.stdout).unwrap();
    let worker_digest = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(&worker).unwrap())
    );
    let mut engine = Opa {
        python,
        worker,
        executable,
        worker_digest: worker_digest.clone(),
        executable_digest:
            "sha256:668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031".into(),
        version: "1.21.1".into(),
        capabilities: caps.clone(),
    };
    let policy = json!({"worker_digest":worker_digest,
        "capabilities_digest":digest("munarium:opa-capabilities:v1", &serde_json::to_vec(&caps).unwrap()),
        "code":"package munarium\nimport rego.v1\ndecision := {\"allow\": input.amount + 0 <= 10, \"forbid\": false, \"rules\": [\"permit\"], \"predicates\": {}, \"diagnostics\": []}"});
    assert_eq!(
        engine.evaluate(&policy, &json!({"amount":1})).unwrap()["allow"],
        true
    );
    assert_eq!(
        engine.evaluate(&policy, &json!({"amount":20})).unwrap()["allow"],
        false
    );
    assert!(matches!(
        engine.evaluate(&policy, &json!({"amount":"one"})),
        Err(Error::Evaluator)
    ));
    let mut substituted = policy.clone();
    substituted["worker_digest"] = json!("sha256:substituted");
    assert!(matches!(
        engine.evaluate(&substituted, &json!({"amount":1})),
        Err(Error::Evaluator)
    ));
}
