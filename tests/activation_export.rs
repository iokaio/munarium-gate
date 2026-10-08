// SPDX-License-Identifier: Apache-2.0
use serde_json::Value;
use sha2::{Digest, Sha256};
#[test]
fn candidate_export_matches_immutable_bundle_lock() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/stage2-v1");
    let lock: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("vendor-lock.json")).unwrap())
            .unwrap();
    let bundle: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("bundle-lock.json")).unwrap())
            .unwrap();
    assert_eq!(lock["files"], bundle["files"]);
    assert_eq!(
        lock["bundle_sha256"],
        "8aca66588c87107a0c7a7720c68f921dfd2bdcaecf6433728afa4b1c51420aa6"
    );
    let mut aggregate = String::new();
    for (name, expected) in lock["files"].as_object().unwrap() {
        let content = std::fs::read_to_string(root.join(name))
            .unwrap()
            .replace("\r\n", "\n");
        let actual = format!("{:x}", Sha256::digest(content.as_bytes()));
        assert_eq!(expected, &actual);
        aggregate.push_str(&format!("{name}\0{actual}\n"));
    }
    assert_eq!(
        format!("{:x}", Sha256::digest(aggregate.as_bytes())),
        lock["bundle_sha256"]
    );
    assert_eq!(lock["status"], "candidate-not-accepted-not-released");
}
