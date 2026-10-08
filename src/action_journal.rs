// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL action custody. Trusted adapter inputs are not request DTOs or send authority.
use crate::{
    activation::{Store, sqlx, unavailable},
    activation_wire::{self as wire, Error, Result},
};
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::BTreeMap;

/// Independently verified immutable request, decision and currently eligible approval.
/// The future service adapter must fetch these from authenticated owners.
pub struct Admission {
    /// Canonical request assembled by Gate.
    pub request: Value,
    /// Gate's exact decision.
    pub decision: Value,
    /// Current Council approval, checked independently by the adapter.
    pub approval: Value,
    /// Exact Server-acknowledged Council event.
    pub approval_event: Value,
    /// Exact custody acknowledgement, obtained from Server.
    pub approval_ack: Value,
    /// Current bounded UTC seconds.
    pub now: u64,
}
/// A currently verified Warden issuance and worker invocation. Not deserializable.
pub struct Consumption {
    /// Exact grant-issued event obtained from Warden.
    pub grant_event: Value,
    /// Exact Server acknowledgement of that issuance.
    pub grant_ack: Value,
    /// Identity of the authenticated worker invocation.
    pub worker: String,
    /// Additional policy-admitted cumulative buckets and their caps (mandatory cap is added locally).
    pub limits: BTreeMap<String, u64>,
    /// Current bounded UTC seconds.
    pub now: u64,
}
fn id(v: &Value) -> Result<&str> {
    v.as_str().ok_or(Error::Invalid)
}
fn current(a: &Admission) -> Result<()> {
    let r = &a.request;
    let d = &a.decision;
    let p = &a.approval;
    for (v, k) in [
        (r, "action-request"),
        (d, "action-decision"),
        (p, "action-approval"),
        (&a.approval_event, "accountability-event"),
    ] {
        wire::shape(v, k)?;
        wire::scoped(v, &r["operation"]["scope"])?;
    }
    let digest = wire::digest("action-request", r)?;
    if r["intent_digest"] != wire::digest("intent", &r["intent"])?
        || r["context_digest"] != wire::digest("context", &r["context"])?
        || d["request_digest"] != digest
        || p["request_digest"] != digest
        || p["decision_digest"] != wire::digest("action-decision", d)?
        || d["outcome"] != "approval-required"
        || p["approver"]["kind"] != "human"
        || p["approver"] == r["intent"]["origin"]
        || p["approver"] == r["intent"]["actor"]
        || a.approval_event["producer"] != "council"
        || a.approval_event["kind"] != "approval-recorded"
        || a.approval_event["payload"]["approval_digest"] != wire::digest("action-approval", p)?
        || a.approval_event["payload"]["approval"] != p["approval"]
        || r["intent"]["capability_operation"] != "release.publish_approved_artifact"
        || r["context"]["mode"] != "enforce"
    {
        return Err(Error::Refused);
    }
    for k in ["operation", "attempt", "context_digest"] {
        if d[k] != r[k] || p[k] != r[k] || a.approval_event["payload"][k] != r[k] {
            return Err(Error::Refused);
        }
    }
    if a.approval_event["payload"]["request_digest"] != digest
        || p["expires_at"].as_u64().ok_or(Error::Invalid)?
            > p["issued_at"]
                .as_u64()
                .ok_or(Error::Invalid)?
                .saturating_add(300)
    {
        return Err(Error::Refused);
    }
    for (start, end) in [
        (&r["context"]["valid_from"], &r["context"]["expires_at"]),
        (&p["issued_at"], &p["expires_at"]),
    ] {
        if a.now < start.as_u64().ok_or(Error::Invalid)?.saturating_add(2)
            || a.now.saturating_add(2) >= end.as_u64().ok_or(Error::Invalid)?
        {
            return Err(Error::Refused);
        }
    }
    crate::activation_delivery::acknowledge(&a.approval_event, &a.approval_ack)?;
    if a.approval_event["payload_digest"]
        != wire::digest("event-payload", &a.approval_event["payload"])?
    {
        return Err(Error::Refused);
    }
    Ok(())
}
fn binding(a: &Admission) -> Value {
    json!({"request":a.request,"decision":a.decision,"approval":a.approval,"approval_event":a.approval_event,"approval_ack":a.approval_ack})
}
fn artifact_set(request: &Value) -> Result<String> {
    wire::digest(
        "artifact-set",
        &json!({"artifacts":[
            {"kind":"manifest","digest":request["context"]["manifest_digest"]},
            {"kind":"policy","digest":request["context"]["policy_digest"]}
        ]}),
    )
}
async fn cancelled(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &str,
    r: &Value,
    approval: &Value,
) -> Result<bool> {
    Ok(sqlx::query("SELECT 1 FROM gate_action_cancellations WHERE scope=$1 AND operation=$2 AND attempt=$3 AND approval=$4")
        .bind(scope).bind(id(&r["operation"]["id"])?).bind(id(&r["attempt"]["id"])?).bind(wire::raw(approval)?)
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.is_some())
}
async fn append(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &Value,
    payload: Value,
    parents: Vec<String>,
    now: u64,
) -> Result<Value> {
    let key = wire::raw(scope)?;
    let enrollment = sqlx::query("SELECT registration FROM gate_action_enrollment WHERE scope=$1")
        .bind(&key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
    let registration = wire::parse(&enrollment.get::<String, _>("registration"))?;
    let prior=sqlx::query("SELECT sequence,event FROM gate_action_outbox WHERE scope=$1 ORDER BY sequence DESC LIMIT 1").bind(&key).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    let (sequence, predecessor) = if let Some(p) = prior {
        (
            p.get::<i64, _>("sequence") + 1,
            json!(wire::digest(
                "accountability-event",
                &wire::parse(&p.get::<String, _>("event"))?
            )?),
        )
    } else {
        (1, Value::Null)
    };
    let e = json!({"schema_version":1,"type":"accountability-event","profile":"stage2-single-cell-v1","scope":scope,
        "event_id":format!("action-{}-{}",id(&registration["stream"])?,sequence),"producer":"gate","stream":{"scope":scope,"kind":"stream","id":registration["stream"]},
        "source_generation":registration["generation"],"sequence":sequence,"predecessor":predecessor,"occurred_at":now,"clock":"bounded-utc-2s","family":"action",
        "kind":payload["kind"],"payload_digest":wire::digest("event-payload",&payload)?,"payload":payload,"causal_parents":parents});
    wire::shape(&e, "accountability-event")?;
    sqlx::query("INSERT INTO gate_action_outbox(scope,sequence,event) VALUES($1,$2,$3)")
        .bind(key)
        .bind(sequence)
        .bind(wire::raw(&e)?)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(e)
}
impl Store {
    /// Inspect the oldest unacknowledged event without granting execution or skipping history.
    pub async fn action_pending(&self, scope: &Value) -> Result<Option<Value>> {
        sqlx::query("SELECT event FROM gate_action_outbox WHERE scope=$1 AND acknowledgement IS NULL ORDER BY sequence LIMIT 1")
            .bind(wire::raw(scope)?).fetch_optional(&self.pool).await.map_err(unavailable)?
            .map(|r|wire::parse(&r.get::<String,_>("event"))).transpose()
    }
    /// Persist exact custody in source order. The caller must obtain the acknowledgement from Server.
    pub async fn action_ack(&self, scope: &Value, event: &Value, ack: &Value) -> Result<()> {
        crate::activation_delivery::acknowledge(event, ack)?;
        wire::scoped(event, scope)?;
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let sequence = event["sequence"].as_i64().ok_or(Error::Invalid)?;
        let row = sqlx::query(
            "SELECT event,acknowledgement FROM gate_action_outbox WHERE scope=$1 AND sequence=$2",
        )
        .bind(&key)
        .bind(sequence)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        let raw = wire::raw(ack)?;
        if row.get::<String, _>("event") != wire::raw(event)?
            || row
                .get::<Option<String>, _>("acknowledgement")
                .is_some_and(|a| a != raw)
        {
            return Err(Error::Conflict);
        }
        if sqlx::query("SELECT 1 FROM gate_action_outbox WHERE scope=$1 AND sequence<$2 AND acknowledgement IS NULL LIMIT 1").bind(&key).bind(sequence).fetch_optional(&mut *tx).await.map_err(unavailable)?.is_some(){return Err(Error::Refused);}
        sqlx::query(
            "UPDATE gate_action_outbox SET acknowledgement=$3 WHERE scope=$1 AND sequence=$2",
        )
        .bind(key)
        .bind(sequence)
        .bind(raw)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Pin an independently enrolled dedicated action stream once; cannot reset history.
    pub async fn action_enroll(&self, scope: &Value, stream: &str, generation: u64) -> Result<()> {
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let registration = wire::raw(&json!({"stream":stream,"generation":generation}))?;
        if stream.is_empty()
            || stream.len() > 96
            || !stream
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._/-".contains(&b))
            || generation == 0
            || generation > 9007199254740991
        {
            return Err(Error::Invalid);
        }
        sqlx::query("INSERT INTO gate_action_enrollment(scope,registration) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(&key).bind(&registration).execute(&mut *tx).await.map_err(unavailable)?;
        let old = sqlx::query("SELECT registration FROM gate_action_enrollment WHERE scope=$1")
            .bind(key)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if old.get::<String, _>("registration") != registration {
            return Err(Error::Conflict);
        }
        tx.commit().await.map_err(unavailable)
    }
    /// Establish one immutable operation/attempt claim and its canonical event atomically.
    pub async fn action_claim(&self, a: &Admission) -> Result<Value> {
        current(a)?;
        let r = &a.request;
        let scope = &r["operation"]["scope"];
        let key = wire::raw(scope)?;
        let (mut tx, head) = self.locked(&key).await?;
        let encoded = wire::raw(&binding(a))?;
        let old = sqlx::query(
            "SELECT binding,claim FROM gate_action_claims WHERE scope=$1 AND operation=$2",
        )
        .bind(&key)
        .bind(id(&r["operation"]["id"])?)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        if let Some(old) = old {
            if old.get::<String, _>("binding") != encoded {
                return Err(Error::Conflict);
            }
            return wire::parse(&old.get::<String, _>("claim"));
        }
        if head.get::<bool, _>("paused")
            || r["context"]["activation"]["revision"] != head.get::<i64, _>("epoch")
            || artifact_set(r)? != head.get::<String, _>("digest")
            || cancelled(&mut tx, &key, r, &a.approval["approval"]).await?
        {
            return Err(Error::Refused);
        }
        let payload = json!({"kind":"claim-created","operation":r["operation"],"attempt":r["attempt"],"request_digest":wire::digest("action-request",r)?,"context_digest":r["context_digest"],
            "activation_epoch":head.get::<i64,_>("epoch"),"recovery_epoch":r["context"]["recovery"]["revision"],"claim":{"scope":scope,"kind":"claim","id":format!("claim-{}",&wire::digest("claim-binding",&binding(a))?[7..])},"grant_binding_digest":wire::digest("action-request",r)?});
        let claim = append(
            &mut tx,
            scope,
            payload,
            vec![wire::digest("accountability-event", &a.approval_event)?],
            a.now,
        )
        .await?;
        sqlx::query(
            "INSERT INTO gate_action_claims(scope,operation,binding,claim) VALUES($1,$2,$3,$4)",
        )
        .bind(key)
        .bind(id(&r["operation"]["id"])?)
        .bind(encoded)
        .bind(wire::raw(&claim)?)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(claim)
    }
    /// Commit a cancellation even before a claim exists. No final-send route exists in this packet.
    pub async fn action_cancel(
        &self,
        scope: &Value,
        operation: &str,
        attempt: &str,
        approval: &Value,
        withdrawal: &str,
    ) -> Result<Value> {
        wire::scoped(approval, scope)?;
        if operation.is_empty()
            || attempt.is_empty()
            || withdrawal.is_empty()
            || approval["kind"] != "approval"
            || approval["scope"] != *scope
        {
            return Err(Error::Invalid);
        }
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let receipt = json!({"scope":scope,"operation_id":operation,"attempt_id":attempt,"approval":approval,"withdrawal_id":withdrawal,"status":"cancelled","execution_enabled":false});
        let raw = wire::raw(&receipt)?;
        sqlx::query("INSERT INTO gate_action_cancellations(scope,operation,attempt,approval,withdrawal,receipt) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(&key).bind(operation).bind(attempt).bind(wire::raw(approval)?).bind(withdrawal).bind(&raw).execute(&mut *tx).await.map_err(unavailable)?;
        let old=sqlx::query("SELECT receipt FROM gate_action_cancellations WHERE scope=$1 AND operation=$2 AND attempt=$3 AND approval=$4")
            .bind(key).bind(operation).bind(attempt).bind(wire::raw(approval)?).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(Error::Conflict)?;
        if old.get::<String, _>("receipt") != raw {
            return Err(Error::Conflict);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(receipt)
    }
    /// Consume once, bind one worker, reserve all limits and append consumption/predispatch together.
    /// The result is durable custody, never permission to send.
    pub async fn action_consume(&self, a: &Admission, c: &Consumption) -> Result<Value> {
        current(a)?;
        if a.now != c.now {
            return Err(Error::Refused);
        }
        wire::shape(&c.grant_event, "accountability-event")?;
        let r = &a.request;
        let scope = &r["operation"]["scope"];
        wire::scoped(&c.grant_event, scope)?;
        crate::activation_delivery::acknowledge(&c.grant_event, &c.grant_ack)?;
        let g = &c.grant_event["payload"];
        if c.grant_event["producer"] != "warden"
            || c.grant_event["kind"] != "grant-issued"
            || c.grant_event["payload_digest"] != wire::digest("event-payload", g)?
            || c.now.saturating_add(2) >= g["expires_at"].as_u64().ok_or(Error::Invalid)?
        {
            return Err(Error::Refused);
        }
        let key = wire::raw(scope)?;
        let (mut tx, head) = self.locked(&key).await?;
        let row=sqlx::query("SELECT binding,claim,consumption FROM gate_action_claims WHERE scope=$1 AND operation=$2").bind(&key).bind(id(&r["operation"]["id"])?).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(Error::Refused)?;
        if row.get::<String, _>("binding") != wire::raw(&binding(a))? {
            return Err(Error::Conflict);
        }
        let claim = wire::parse(&row.get::<String, _>("claim"))?;
        for k in [
            "operation",
            "attempt",
            "request_digest",
            "context_digest",
            "activation_epoch",
            "recovery_epoch",
            "claim",
        ] {
            if g[k] != claim["payload"][k] {
                return Err(Error::Refused);
            }
        }
        let identity = json!({"grant_event":c.grant_event,"grant_ack":c.grant_ack,"worker":c.worker,"limits":c.limits});
        if let Some(raw) = row.get::<Option<String>, _>("consumption") {
            let old = wire::parse(&raw)?;
            if old["binding"] != identity {
                return Err(Error::Conflict);
            }
            return Ok(old);
        }
        if head.get::<bool, _>("paused")
            || g["activation_epoch"] != head.get::<i64, _>("epoch")
            || artifact_set(r)? != head.get::<String, _>("digest")
            || cancelled(&mut tx, &key, r, &a.approval["approval"]).await?
        {
            return Err(Error::Refused);
        }
        let window = c.now / 3600 * 3600;
        let target = wire::raw(&r["intent"]["target"])?;
        let mut limits = BTreeMap::from([(format!("target:{target}"), 2u64)]);
        if c.limits.len() > 31 {
            return Err(Error::Invalid);
        }
        for (bucket, limit) in &c.limits {
            if bucket.is_empty() || bucket.len() > 256 || *limit == 0 || *limit > 9007199254740991 {
                return Err(Error::Invalid);
            }
            limits.insert(format!("policy:{bucket}"), *limit);
        }
        let mut reservations = Vec::new();
        for (bucket, limit) in limits {
            let count=sqlx::query("SELECT COUNT(*) AS charged FROM gate_action_reservations WHERE scope=$1 AND bucket=$2 AND (unresolved OR window_start=$3)")
                .bind(&key).bind(&bucket).bind(window as i64).fetch_one(&mut *tx).await.map_err(unavailable)?.get::<i64,_>("charged");
            if count as u64 >= limit {
                return Err(Error::Refused);
            }
            sqlx::query("INSERT INTO gate_action_reservations(scope,operation,bucket,window_start) VALUES($1,$2,$3,$4)")
                .bind(&key).bind(id(&r["operation"]["id"])?).bind(&bucket).bind(window as i64).execute(&mut *tx).await.map_err(unavailable)?;
            reservations.push(json!({"reservation":{"kind":"reservation","scope":scope,"id":format!("r-{}",&wire::digest("reservation",&json!({"claim":g["claim"],"bucket":bucket}))?[7..])},"target":r["intent"]["target"],"root":r["intent"]["task"]["root"],"window_start":window,"units":1}));
        }
        sqlx::query("INSERT INTO gate_action_grants(scope,grant_id,operation) VALUES($1,$2,$3)")
            .bind(&key)
            .bind(id(&g["grant"]["id"])?)
            .bind(id(&r["operation"]["id"])?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let mut payload = claim["payload"].clone();
        payload
            .as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("grant_binding_digest");
        payload["kind"] = json!("consumption-reserved");
        payload["grant"] = g["grant"].clone();
        payload["worker"] = json!(c.worker);
        payload["worker_fence"] = json!(1);
        payload["reservations"] = json!(reservations);
        let consumption = append(
            &mut tx,
            scope,
            payload,
            vec![wire::digest("accountability-event", &c.grant_event)?],
            c.now,
        )
        .await?;
        let mut payload = claim["payload"].clone();
        payload
            .as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("grant_binding_digest");
        payload["kind"] = json!("predispatch");
        payload["grant"] = g["grant"].clone();
        payload["consumption_event_digest"] =
            json!(wire::digest("accountability-event", &consumption)?);
        let predispatch = append(
            &mut tx,
            scope,
            payload,
            vec![wire::digest("accountability-event", &consumption)?],
            c.now,
        )
        .await?;
        let result = json!({"binding":identity,"consumption":consumption,"predispatch":predispatch,"execution_enabled":false});
        sqlx::query("UPDATE gate_action_claims SET consumption=$3 WHERE scope=$1 AND operation=$2")
            .bind(key)
            .bind(id(&r["operation"]["id"])?)
            .bind(wire::raw(&result)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(result)
    }
    /// Read immutable action custody for recovery; lookup never acquires a worker or refunds capacity.
    pub async fn action_lookup(&self, scope: &Value, operation: &str) -> Result<Value> {
        let r=sqlx::query("SELECT binding,claim,consumption FROM gate_action_claims WHERE scope=$1 AND operation=$2").bind(wire::raw(scope)?).bind(operation).fetch_optional(&self.pool).await.map_err(unavailable)?.ok_or(Error::Refused)?;
        Ok(
            json!({"binding":wire::parse(&r.get::<String,_>("binding"))?,"claim":wire::parse(&r.get::<String,_>("claim"))?,"consumption":r.get::<Option<String>,_>("consumption").map(|s|wire::parse(&s)).transpose()?,"execution_enabled":false}),
        )
    }
}
