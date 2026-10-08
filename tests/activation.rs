// SPDX-License-Identifier: Apache-2.0
use serde_json::{Value, json};
fn fixture() -> Value {
    serde_json::from_str(include_str!("../contracts/stage2-v1/vectors.json")).unwrap()
}
fn authority(t: &Value) -> wire::Authority {
    wire::Authority {
        scope: t["scope"].clone(),
        ratified: json!({"ratified":true,"transition":t,"transition_digest":wire::digest("activation",t).unwrap()}),
        now: 1000,
    }
}
fn receipt(t: &Value, owner: &str, phase: &str) -> Value {
    let mut r = fixture()["records"]["pause"].clone();
    for k in [
        "transition",
        "prior_epoch",
        "successor_epoch",
        "artifact_set_digest",
        "participant_set_digest",
    ] {
        r[k] = t[k].clone();
    }
    r["transition_digest"] = json!(wire::digest("activation", t).unwrap());
    r["participant"] = json!(owner);
    r["phase"] = json!(phase);
    r
}
fn head(t: &Value, owner: &str) -> Value {
    json!({"participant":owner,"scope":t["scope"],"epoch":t["successor_epoch"],"artifact_set_digest":t["artifact_set_digest"]})
}
#[test]
fn exact_activation_vector_and_negative_bindings() {
    let v = fixture();
    let t = &v["records"]["activation"];
    assert_eq!(
        wire::raw(t).unwrap(),
        v["canonical"]["activation"].as_str().unwrap()
    );
    assert_eq!(
        wire::digest("activation", t).unwrap(),
        v["records"]["pause"]["transition_digest"]
    );
    wire::validate(&authority(t), t).unwrap();
    for owner in ["registry", "server", "warden", "gate"] {
        wire::check_receipt(
            t,
            &v["records"][format!("{owner}-receipt")],
            owner,
            "applied",
        )
        .unwrap();
    }
    assert!(wire::parse("{\"x\":1,\"x\":1}").is_err());
    let mut a = authority(t);
    a.now = 1298;
    assert!(wire::validate(&a, t).is_err());
    a.now = 991;
    assert!(wire::validate(&a, t).is_err());
    a.now = 1000;
    a.ratified["ratified"] = json!(false);
    assert!(wire::validate(&a, t).is_err());
    let mut changed = t.clone();
    changed["participants"] = json!(["gate", "registry"]);
    assert!(wire::validate(&authority(&changed), &changed).is_err());
    let mut foreign = t.clone();
    foreign["ratification"]["scope"]["tenant"] = json!("foreign");
    assert!(wire::validate(&authority(&foreign), &foreign).is_err());
}

use munarium_gate::{
    activation::{Evidence, Store},
    activation_wire as wire,
};
fn evidence(t: &Value) -> Evidence {
    Evidence {
        receipts: ["registry", "server", "warden"]
            .map(|o| receipt(t, o, "applied"))
            .into(),
        heads: ["registry", "server", "warden"].map(|o| head(t, o)).into(),
    }
}
fn completion(t: &Value) -> Value {
    json!({"transition":t,"pause":receipt(t,"gate","paused"),"receipts":(["gate","registry","server","warden"].map(|o|receipt(t,o,"applied")))})
}
fn unique_transition() -> Value {
    let mut t = fixture()["records"]["activation"].clone();
    let scope = json!({"domain":"fixture-domain","tenant":"tenant-a","deployment":"fixture-deployment",
        "cell":format!("test-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())});
    t["scope"] = scope.clone();
    t["transition"]["scope"] = scope.clone();
    t["ratification"]["scope"] = scope;
    t
}
#[tokio::test]
#[ignore = "requires isolated GATE_TEST_DATABASE_URL; CI selects explicitly"]
async fn postgres_barrier_restart_refusals_and_exact_resume() {
    let url = std::env::var("GATE_TEST_DATABASE_URL").expect("isolated test PostgreSQL required");
    let mut db = Store::open(&url).await.unwrap();
    let t = unique_transition();
    let auth = authority(&t);
    let scope = &auth.scope;
    db.initialize(scope, 1, t["prior_artifact_set_digest"].as_str().unwrap())
        .await
        .unwrap();
    assert!(db.apply(&auth, &t).await.is_err());
    assert!(
        db.resume(&auth, &completion(&t), &evidence(&t))
            .await
            .is_err()
    );
    let paused = db.pause(&auth, &t).await.unwrap();
    assert_eq!(paused, receipt(&t, "gate", "paused"));
    drop(db);
    db = Store::open(&url).await.unwrap();
    assert_eq!(db.pause(&auth, &t).await.unwrap(), paused);
    assert_eq!(db.pending(scope).await.unwrap().len(), 1);
    assert_eq!(db.head(scope).await.unwrap()["paused"], true);
    let applied = db.apply(&auth, &t).await.unwrap();
    drop(db);
    db = Store::open(&url).await.unwrap();
    assert_eq!(db.apply(&auth, &t).await.unwrap(), applied);
    assert_eq!(db.head(scope).await.unwrap()["paused"], true);
    let mut missing = evidence(&t);
    missing.receipts.pop();
    assert!(db.resume(&auth, &completion(&t), &missing).await.is_err());
    let mut duplicate = completion(&t);
    duplicate["receipts"][1] = duplicate["receipts"][0].clone();
    assert!(db.resume(&auth, &duplicate, &evidence(&t)).await.is_err());
    let mut stale = evidence(&t);
    stale.heads[0]["epoch"] = json!(1);
    assert!(db.resume(&auth, &completion(&t), &stale).await.is_err());
    let mut forged = evidence(&t);
    forged.receipts[0]["transition_digest"] = json!(format!("sha256:{}", "a".repeat(64)));
    assert!(db.resume(&auth, &completion(&t), &forged).await.is_err());
    let mut expired = authority(&t);
    expired.now = 1300;
    assert!(
        db.resume(&expired, &completion(&t), &evidence(&t))
            .await
            .is_err()
    );
    assert_eq!(db.head(scope).await.unwrap()["paused"], true);
    let reply = db
        .resume(&auth, &completion(&t), &evidence(&t))
        .await
        .unwrap();
    assert_eq!(reply["resumed"], true);
    assert_eq!(reply["execution_enabled"], false);
    assert_eq!(
        db.resume(&auth, &completion(&t), &evidence(&t))
            .await
            .unwrap(),
        reply
    );
    assert_eq!(db.pending(scope).await.unwrap().len(), 3);
    db.initialize(scope, 1, t["prior_artifact_set_digest"].as_str().unwrap())
        .await
        .unwrap();
    assert!(
        db.initialize(scope, 2, t["artifact_set_digest"].as_str().unwrap())
            .await
            .is_err()
    );
    let mut next = t.clone();
    next["transition"]["id"] = json!("next");
    next["prior_epoch"] = json!(2);
    next["successor_epoch"] = json!(3);
    next["prior_artifact_set_digest"] = next["artifact_set_digest"].clone();
    db.pause(&authority(&next), &next).await.unwrap();
    assert!(
        db.resume(&auth, &completion(&t), &evidence(&t))
            .await
            .is_err()
    );
    assert_eq!(db.head(scope).await.unwrap()["paused"], true);
    let mut foreign = scope.clone();
    foreign["tenant"] = json!("foreign");
    assert!(db.lookup(&foreign, "transition-a", true).await.is_err());
}
#[tokio::test]
#[ignore = "requires isolated GATE_TEST_DATABASE_URL; CI selects explicitly"]
async fn postgres_competing_transitions_have_one_winner() {
    let url = std::env::var("GATE_TEST_DATABASE_URL").expect("isolated test PostgreSQL required");
    let db = Store::open(&url).await.unwrap();
    let other = Store::open(&url).await.unwrap();
    let t = unique_transition();
    let mut rival = t.clone();
    rival["transition"]["id"] = json!("rival");
    let a = authority(&t);
    let b = authority(&rival);
    db.initialize(
        &a.scope,
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
    )
    .await
    .unwrap();
    let (x, y) = tokio::join!(db.pause(&a, &t), other.pause(&b, &rival));
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    assert_eq!(db.pending(&a.scope).await.unwrap().len(), 1);
}
