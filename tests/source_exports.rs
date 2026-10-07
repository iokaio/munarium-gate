// SPDX-License-Identifier: Apache-2.0
use sha2::{Digest, Sha256};
#[test]
fn warden_exports_match_reviewed_source_locks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for export in ["warden-identity", "warden-transport"] {
        let dir = root.join("vendor").join(export);
        let lock: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("source-lock.json")).unwrap()).unwrap();
        for (path, expected) in lock["files"].as_object().unwrap() {
            let raw = std::fs::read(dir.join(path)).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(raw)),
                expected.as_str().unwrap(),
                "{export}/{path}"
            );
        }
    }
}
