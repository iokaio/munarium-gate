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

fn ack(event: &Value) -> Value {
    let mut a = fixture()["records"]["ack"].clone();
    a["scope"] = event["scope"].clone();
    a["ledger"]["scope"] = event["scope"].clone();
    a["event_id"] = event["event_id"].clone();
    a["payload_digest"] = event["payload_digest"].clone();
    a["event_digest"] = json!(wire::digest("accountability-event", event).unwrap());
    a
}
fn rescope(v: &mut Value, scope: &Value) {
    match v {
        Value::Object(m) => {
            if m.contains_key("scope") {
                m.insert("scope".into(), scope.clone());
            }
            for (k, c) in m {
                if k != "scope" {
                    rescope(c, scope);
                }
            }
        }
        Value::Array(a) => {
            for c in a {
                rescope(c, scope)
            }
        }
        _ => {}
    }
}
fn admission(scope: &Value, operation: &str, now: u64) -> munarium_gate::action_journal::Admission {
    let mut v = fixture()["records"].clone();
    rescope(&mut v, scope);
    let r = &mut v["request"];
    r["operation"]["id"] = json!(operation);
    r["context"]["valid_from"] = json!(now - 10);
    r["context"]["expires_at"] = json!(now + 300);
    r["intent_digest"] = json!(wire::digest("intent", &r["intent"]).unwrap());
    r["context_digest"] = json!(wire::digest("context", &r["context"]).unwrap());
    let r = r.clone();
    let d = &mut v["decision"];
    for k in ["operation", "attempt", "context_digest"] {
        d[k] = r[k].clone();
    }
    d["request_digest"] = json!(wire::digest("action-request", &r).unwrap());
    let d = d.clone();
    let p = &mut v["approval"];
    for k in ["operation", "attempt", "context_digest", "request_digest"] {
        p[k] = d[k].clone();
    }
    p["approval"]["id"] = json!(format!("approval-{operation}"));
    p["decision_digest"] = json!(wire::digest("action-decision", &d).unwrap());
    p["issued_at"] = json!(now - 10);
    p["expires_at"] = json!(now + 290);
    let p = p.clone();
    let e = &mut v["approval-recorded"];
    for k in ["operation", "attempt", "request_digest", "context_digest"] {
        e["payload"][k] = p[k].clone();
    }
    e["payload"]["approval"] = p["approval"].clone();
    e["payload"]["approval_digest"] = json!(wire::digest("action-approval", &p).unwrap());
    e["payload_digest"] = json!(wire::digest("event-payload", &e["payload"]).unwrap());
    munarium_gate::action_journal::Admission {
        request: r,
        decision: d,
        approval: p,
        approval_event: e.clone(),
        approval_ack: ack(e),
        now,
    }
}
fn consumption(
    claim: &Value,
    now: u64,
    worker: &str,
) -> munarium_gate::action_journal::Consumption {
    let mut e = fixture()["records"]["grant-issued"].clone();
    rescope(&mut e, &claim["scope"]);
    for k in [
        "operation",
        "attempt",
        "request_digest",
        "context_digest",
        "activation_epoch",
        "recovery_epoch",
        "claim",
    ] {
        e["payload"][k] = claim["payload"][k].clone();
    }
    e["payload"]["grant"]["id"] = json!(format!(
        "grant-{}",
        claim["payload"]["operation"]["id"].as_str().unwrap()
    ));
    e["payload"]["expires_at"] = json!(now + 20);
    e["payload_digest"] = json!(wire::digest("event-payload", &e["payload"]).unwrap());
    munarium_gate::action_journal::Consumption {
        grant_ack: ack(&e),
        grant_event: e,
        worker: worker.into(),
        limits: Default::default(),
        now,
    }
}
#[tokio::test]
#[ignore = "requires isolated GATE_TEST_DATABASE_URL; CI selects explicitly"]
async fn postgres_action_races_cancellation_pause_and_unresolved_capacity() {
    let url = std::env::var("GATE_TEST_DATABASE_URL").unwrap();
    let db = Store::open(&url).await.unwrap();
    let t = unique_transition();
    let auth = authority(&t);
    let scope = &auth.scope;
    db.initialize(scope, 1, t["prior_artifact_set_digest"].as_str().unwrap())
        .await
        .unwrap();
    db.action_enroll(scope, "gate-actions", 1).await.unwrap();
    let a = admission(scope, "one", 1000);
    assert!(db.action_claim(&a).await.is_err());
    db.pause(&auth, &t).await.unwrap();
    db.apply(&auth, &t).await.unwrap();
    db.resume(&auth, &completion(&t), &evidence(&t))
        .await
        .unwrap();
    let (x, y) = tokio::join!(db.action_claim(&a), db.action_claim(&a));
    let claim = x.unwrap();
    assert_eq!(claim, y.unwrap());
    let c = consumption(&claim, 1000, "worker-one");
    let other = consumption(&claim, 1000, "worker-two");
    let (x, y) = tokio::join!(db.action_consume(&a, &c), db.action_consume(&a, &other));
    assert_eq!(x.is_ok() as u8 + y.is_ok() as u8, 1);
    let (winner, result) = if let Ok(r) = x {
        (&c, r)
    } else {
        (&other, y.unwrap())
    };
    assert_eq!(db.action_consume(&a, winner).await.unwrap(), result);
    assert_eq!(result["execution_enabled"], false);
    let cancelled = admission(scope, "cancelled", 1000);
    db.action_cancel(
        scope,
        "cancelled",
        "attempt-a",
        &cancelled.approval["approval"],
        "withdraw-a",
    )
    .await
    .unwrap();
    assert!(db.action_claim(&cancelled).await.is_err());
    let b = admission(scope, "two", 1000);
    let claim_b = db.action_claim(&b).await.unwrap();
    let mut c_b = consumption(&claim_b, 1000, "worker-b");
    c_b.limits.insert("root-cap".into(), 1);
    db.action_consume(&b, &c_b).await.unwrap();
    drop(db);
    let db = Store::open(&url).await.unwrap();
    assert_eq!(
        db.action_lookup(scope, "one").await.unwrap()["consumption"],
        result
    );
    let later = admission(scope, "three", 4600);
    let claim_later = db.action_claim(&later).await.unwrap();
    let c_later = consumption(&claim_later, 4600, "worker-later");
    assert!(db.action_consume(&later, &c_later).await.is_err());
    assert!(db.action_lookup(scope, "three").await.unwrap()["consumption"].is_null());
    let mut altered = admission(scope, "one", 1000);
    altered.request["attempt"]["id"] = json!("new-attempt");
    assert!(db.action_claim(&altered).await.is_err());
    assert!(db.action_enroll(scope, "changed-stream", 1).await.is_err());
    let foreign = json!({"domain":"fixture-domain","tenant":"foreign","deployment":"fixture-deployment","cell":"other"});
    assert!(db.action_lookup(&foreign, "one").await.is_err());
}

#[tokio::test]
#[ignore = "requires isolated GATE_TEST_DATABASE_URL; CI selects explicitly"]
async fn postgres_capacity_race_rolls_back_all_buckets_and_orders_audit() {
    let url = std::env::var("GATE_TEST_DATABASE_URL").unwrap();
    let db = Store::open(&url).await.unwrap();
    let t = unique_transition();
    let auth = authority(&t);
    let scope = &auth.scope;
    db.initialize(scope, 1, t["prior_artifact_set_digest"].as_str().unwrap())
        .await
        .unwrap();
    db.action_enroll(scope, "action-races", 1).await.unwrap();
    db.pause(&auth, &t).await.unwrap();
    db.apply(&auth, &t).await.unwrap();
    db.resume(&auth, &completion(&t), &evidence(&t))
        .await
        .unwrap();
    let a = admission(scope, "a", 1000);
    let b = admission(scope, "b", 1000);
    let c = admission(scope, "c", 1000);
    let ca = db.action_claim(&a).await.unwrap();
    let cb = db.action_claim(&b).await.unwrap();
    let cc = db.action_claim(&c).await.unwrap();
    let ga = consumption(&ca, 1000, "a");
    let gb = consumption(&cb, 1000, "b");
    let mut gc = consumption(&cc, 1000, "c");
    gc.limits.insert("extra".into(), 1);
    let (ra, rb, rc) = tokio::join!(
        db.action_consume(&a, &ga),
        db.action_consume(&b, &gb),
        db.action_consume(&c, &gc)
    );
    assert_eq!(
        [ra.is_ok(), rb.is_ok(), rc.is_ok()]
            .into_iter()
            .filter(|b| *b)
            .count(),
        2
    );
    let pending = db.action_pending(scope).await.unwrap().unwrap();
    assert_eq!(pending, ca);
    assert!(db.action_ack(scope, &cb, &ack(&cb)).await.is_err());
    let mut wrong = ack(&ca);
    wrong["payload_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert!(db.action_ack(scope, &ca, &wrong).await.is_err());
    db.action_ack(scope, &ca, &ack(&ca)).await.unwrap();
    db.action_ack(scope, &ca, &ack(&ca)).await.unwrap();
    assert_eq!(db.action_pending(scope).await.unwrap(), Some(cb));
    // Failed consumption must not retain a grant, policy bucket or partial outbox.
    let failed = if ra.is_err() {
        "a"
    } else if rb.is_err() {
        "b"
    } else {
        "c"
    };
    assert!(db.action_lookup(scope, failed).await.unwrap()["consumption"].is_null());
    let rollback = admission(scope, "rollback", 1000);
    let rollback_claim = db.action_claim(&rollback).await.unwrap();
    let mut rollback_grant = consumption(&rollback_claim, 1000, "rollback-worker");
    rollback_grant.limits.insert("rollback-probe".into(), 1);
    assert!(db.action_consume(&rollback, &rollback_grant).await.is_err());
    let pool = sqlx_postgres::PgPool::connect(&url).await.unwrap();
    use sqlx_core::row::Row;
    for table in ["gate_action_reservations", "gate_action_grants"] {
        let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE scope=$1 AND operation=$2");
        let row = sqlx_core::query::query(&sql)
            .bind(wire::raw(scope).unwrap())
            .bind("rollback")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            row.get::<i64, _>("n"),
            0,
            "failed transaction must not retain partial writes"
        );
    }
    let row =
        sqlx_core::query::query("SELECT COUNT(*) AS n FROM gate_action_outbox WHERE scope=$1")
            .bind(wire::raw(scope).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row.get::<i64, _>("n"),
        8,
        "four claims and two complete consumption pairs only"
    );
    // An extra exhausted bucket is checked in the same transaction as target capacity.
    let mut next = admission(scope, "paused", 1000);
    next.request["context"]["activation"]["revision"] = json!(99);
    assert!(db.action_claim(&next).await.is_err());
    let pending = admission(scope, "before-pause", 1000);
    let claim = db.action_claim(&pending).await.unwrap();
    let mut transition = t.clone();
    transition["transition"]["id"] = json!("next-transition");
    transition["prior_epoch"] = json!(2);
    transition["successor_epoch"] = json!(3);
    transition["prior_artifact_set_digest"] = t["artifact_set_digest"].clone();
    db.pause(&authority(&transition), &transition)
        .await
        .unwrap();
    assert!(
        db.action_consume(&pending, &consumption(&claim, 1000, "paused-worker"))
            .await
            .is_err()
    );
    db.action_cancel(
        scope,
        "before-pause",
        "attempt-a",
        &pending.approval["approval"],
        "withdraw-before-send",
    )
    .await
    .unwrap();
    assert!(db.action_lookup(scope, "before-pause").await.unwrap()["consumption"].is_null());
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

#[tokio::test]
#[ignore = "requires isolated GATE_TEST_DATABASE_URL; CI selects explicitly"]
async fn delivery_retries_exact_event_and_rejects_wrong_custody() {
    let url = std::env::var("GATE_TEST_DATABASE_URL").unwrap();
    let db = Store::open(&url).await.unwrap();
    let t = unique_transition();
    let a = authority(&t);
    db.initialize(
        &a.scope,
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
    )
    .await
    .unwrap();
    db.pause(&a, &t).await.unwrap();
    db.apply(&a, &t).await.unwrap();
    let registration = json!({"stream":"activation-delivery","generation":1});
    let event = db
        .delivery_next(&a.scope, &registration, 1001)
        .await
        .unwrap()
        .unwrap();
    drop(db);
    let db = Store::open(&url).await.unwrap();
    assert_eq!(
        db.delivery_next(&a.scope, &registration, 1099)
            .await
            .unwrap(),
        Some(event.clone())
    );
    assert!(
        db.delivery_next(
            &a.scope,
            &json!({"stream":"activation-delivery","generation":2}),
            1099
        )
        .await
        .is_err()
    );
    let mut ack = fixture()["records"]["ack"].clone();
    ack["scope"] = a.scope.clone();
    ack["ledger"]["scope"] = a.scope.clone();
    ack["event_id"] = event["event_id"].clone();
    ack["payload_digest"] = event["payload_digest"].clone();
    ack["event_digest"] = json!(wire::digest("accountability-event", &event).unwrap());
    let mut wrong = ack.clone();
    wrong["position"] = json!(0);
    assert!(db.delivery_ack(&a.scope, &event, &wrong).await.is_err());
    wrong = ack.clone();
    wrong["event_id"] = json!("wrong");
    assert!(db.delivery_ack(&a.scope, &event, &wrong).await.is_err());
    wrong = ack.clone();
    wrong["ledger"]["scope"]["tenant"] = json!("foreign");
    assert!(db.delivery_ack(&a.scope, &event, &wrong).await.is_err());
    assert_eq!(
        db.delivery_next(&a.scope, &registration, 1100)
            .await
            .unwrap(),
        Some(event.clone())
    );
    db.delivery_ack(&a.scope, &event, &ack).await.unwrap();
    db.delivery_ack(&a.scope, &event, &ack).await.unwrap();
    assert!(
        db.delivery_next(&a.scope, &registration, 1101)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!db.pending(&a.scope).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires isolated GATE_TEST_DATABASE_URL; CI selects explicitly"]
async fn final_send_exact_custody_races_lost_reply_cancellation_and_generation() {
    use munarium_gate::final_send::Custody;
    let url = std::env::var("GATE_TEST_DATABASE_URL").unwrap();
    let db = Store::open(&url).await.unwrap();
    let t = unique_transition();
    let auth = authority(&t);
    let scope = &auth.scope;
    db.initialize(scope, 1, t["prior_artifact_set_digest"].as_str().unwrap())
        .await
        .unwrap();
    db.action_enroll(scope, "final-send", 1).await.unwrap();
    db.pause(&auth, &t).await.unwrap();
    db.apply(&auth, &t).await.unwrap();
    db.resume(&auth, &completion(&t), &evidence(&t))
        .await
        .unwrap();
    db.execution_generation(scope, 1).await.unwrap();
    let a = admission(scope, "live-final", 1000);
    let claim = db.action_claim(&a).await.unwrap();
    let consumed = db
        .action_consume(&a, &consumption(&claim, 1000, "connector"))
        .await
        .unwrap();
    let mut custody = Custody {
        grant: consumed["consumption"]["payload"]["grant"].clone(),
        invocation: json!({"scope":scope,"kind":"invocation","id":"invocation"}),
        worker: "connector".into(),
        fence: 1,
        expires_at: 1005,
        recovery: 1,
    };
    assert!(
        db.action_final(&a, &custody).await.is_err(),
        "missing predispatch custody refuses"
    );
    while let Some(e) = db.action_pending(scope).await.unwrap() {
        db.action_ack(scope, &e, &ack(&e)).await.unwrap();
    }
    custody.fence = 2;
    assert!(db.action_final(&a, &custody).await.is_err());
    custody.fence = 1;
    custody.expires_at = 1002;
    assert!(db.action_final(&a, &custody).await.is_err());
    custody.expires_at = 1005;
    custody.recovery = 2;
    assert!(db.action_final(&a, &custody).await.is_err());
    custody.recovery = 1;
    let (first, second) =
        tokio::join!(db.action_final(&a, &custody), db.action_final(&a, &custody));
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| r["send_permitted"] == true)
            .count(),
        1
    );
    let event = &results
        .iter()
        .find(|r| r["send_permitted"] == true)
        .unwrap()["send_intent"];
    wire::shape(event, "accountability-event").unwrap();
    drop(db);
    let db = Store::open(&url).await.unwrap();
    assert_eq!(
        db.action_final(&a, &custody).await.unwrap()["send_permitted"],
        false,
        "lost reply never replaced after reopen"
    );
    assert_eq!(
        db.action_dispatch(scope, "live-final").await.unwrap()["send_permitted"],
        false
    );
    let cancel = db
        .action_cancel(
            scope,
            "live-final",
            "attempt-a",
            &a.approval["approval"],
            "withdraw-late",
        )
        .await
        .unwrap();
    assert_eq!(cancel["status"], "too-late");
    let outcome = db
        .action_unresolved(scope, "live-final", 1001)
        .await
        .unwrap();
    wire::shape(&outcome, "accountability-event").unwrap();
    assert_eq!(
        db.action_unresolved(scope, "live-final", 1002)
            .await
            .unwrap(),
        outcome
    );
    assert!(
        db.execution_generation(scope, 2).await.is_err(),
        "new external generation cannot reopen old storage"
    );
    let a = admission(scope, "cancel-wins", 1000);
    let claim = db.action_claim(&a).await.unwrap();
    let consumed = db
        .action_consume(&a, &consumption(&claim, 1000, "connector"))
        .await
        .unwrap();
    while let Some(e) = db.action_pending(scope).await.unwrap() {
        db.action_ack(scope, &e, &ack(&e)).await.unwrap();
    }
    custody.grant = consumed["consumption"]["payload"]["grant"].clone();
    db.action_cancel(
        scope,
        "cancel-wins",
        "attempt-a",
        &a.approval["approval"],
        "withdraw-early",
    )
    .await
    .unwrap();
    assert!(db.action_final(&a, &custody).await.is_err());
    assert!(db.action_dispatch(scope, "cancel-wins").await.unwrap()["send_intent"].is_null());
    let original = admission(scope, "live-final", 1000);
    let request = &original.request;
    let mut receipt = json!({"operation":request["operation"],"request_digest":wire::digest("action-request",request).unwrap(),
        "target":request["intent"]["target"],"effect_key":"live-final","recovery_epoch":1,"worker_fence":1,
        "version":2,"content_digest":request["intent"]["parameters"]["artifact_digest"],"status":"completed"});
    receipt["version"] = json!(3);
    assert!(
        db.action_reconcile(scope, "live-final", &receipt, 1001)
            .await
            .is_err()
    );
    receipt["version"] = json!(2);
    let reconciled = db
        .action_reconcile(scope, "live-final", &receipt, 1001)
        .await
        .unwrap();
    assert_eq!(
        db.action_reconcile(scope, "live-final", &receipt, 1002)
            .await
            .unwrap(),
        reconciled
    );
    assert_eq!(
        db.action_dispatch(scope, "live-final").await.unwrap()["outcome"],
        outcome,
        "original uncertainty remains append-only"
    );
    let same_hour = admission(scope, "same-hour", 1000);
    let claim = db.action_claim(&same_hour).await.unwrap();
    assert!(
        db.action_consume(&same_hour, &consumption(&claim, 1000, "connector"))
            .await
            .is_err(),
        "completed admission stays charged in its original hour"
    );
    let next_hour = admission(scope, "next-hour", 4600);
    let claim = db.action_claim(&next_hour).await.unwrap();
    db.action_consume(&next_hour, &consumption(&claim, 4600, "connector"))
        .await
        .unwrap();
    let over = admission(scope, "still-uncertain", 4600);
    let claim = db.action_claim(&over).await.unwrap();
    assert!(
        db.action_consume(&over, &consumption(&claim, 4600, "connector"))
            .await
            .is_err(),
        "unsettled cancellation still carries into the next hour"
    );
}
