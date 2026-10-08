// SPDX-License-Identifier: Apache-2.0
//! One-shot final admission. Only a successful first live response permits sending.
use crate::{
    action_journal::{Admission, append, artifact_set, binding, cancelled, current},
    activation::{Store, sqlx, unavailable},
    activation_wire::{self as wire, Error, Result},
};
use serde_json::{Value, json};
use sqlx::Row;

/// Online Warden custody checked by the authenticated adapter, never caller authority.
pub struct Custody {
    /// Exact immutable issued grant reference.
    pub grant: Value,
    /// Connector invocation, qualified to the operation scope.
    pub invocation: Value,
    /// Authenticated connector worker identity.
    pub worker: String,
    /// Exact consumed worker fence.
    pub fence: u64,
    /// Exclusive online custody expiry (at most five seconds from observation).
    pub expires_at: u64,
    /// Independently checked current external recovery generation.
    pub recovery: u64,
}
impl Store {
    /// Settle only from an independently authenticated target observation, retaining prior uncertainty.
    /// No-effect absence is insufficient; this adapter currently settles proven completed effects only.
    pub async fn action_reconcile(
        &self,
        scope: &Value,
        operation: &str,
        receipt: &Value,
        now: u64,
    ) -> Result<Value> {
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let row = sqlx::query(
            "SELECT admission,outcome FROM gate_action_dispatch WHERE scope=$1 AND operation=$2",
        )
        .bind(&key)
        .bind(operation)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        let send = wire::parse(&row.get::<String, _>("admission"))?;
        let outcome = wire::parse(
            &row.get::<Option<String>, _>("outcome")
                .ok_or(Error::Refused)?,
        )?;
        let original =
            sqlx::query("SELECT binding FROM gate_action_claims WHERE scope=$1 AND operation=$2")
                .bind(&key)
                .bind(operation)
                .fetch_one(&mut *tx)
                .await
                .map_err(unavailable)?;
        let original = wire::parse(&original.get::<String, _>("binding"))?;
        let request = &original["request"];
        wire::scoped(receipt, scope)?;
        for k in [
            "operation",
            "request_digest",
            "target",
            "effect_key",
            "recovery_epoch",
            "worker_fence",
        ] {
            if receipt[k] != send["payload"][k] {
                return Err(Error::Refused);
            }
        }
        if receipt["status"] != "completed"
            || receipt["content_digest"] != request["intent"]["parameters"]["artifact_digest"]
            || receipt["version"].as_u64()
                != request["intent"]["target_precondition"]["version"]
                    .as_u64()
                    .and_then(|v| v.checked_add(1))
        {
            return Err(Error::Refused);
        }
        if let Some(old) = sqlx::query(
            "SELECT receipt,event FROM gate_action_reconciliations WHERE scope=$1 AND operation=$2",
        )
        .bind(&key)
        .bind(operation)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        {
            if old.get::<String, _>("receipt") != wire::raw(receipt)? {
                return Err(Error::Conflict);
            }
            return wire::parse(&old.get::<String, _>("event"));
        }
        let mut payload = outcome["payload"].clone();
        payload
            .as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("invocation");
        payload["kind"] = json!("reconciliation");
        payload["effect_status"] = json!("completed");
        payload["prior_outcome_digest"] = json!(wire::digest("accountability-event", &outcome)?);
        payload["evidence"] = json!([{"scope":scope,"kind":"evidence","id":format!("target-{}",&wire::digest("target-observation",receipt)?[7..])}]);
        let event = append(
            &mut tx,
            scope,
            payload,
            vec![wire::digest("accountability-event", &outcome)?],
            now,
        )
        .await?;
        sqlx::query("INSERT INTO gate_action_reconciliations(scope,operation,receipt,event) VALUES($1,$2,$3,$4)")
            .bind(&key).bind(operation).bind(wire::raw(receipt)?).bind(wire::raw(&event)?).execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query(
            "UPDATE gate_action_reservations SET unresolved=FALSE WHERE scope=$1 AND operation=$2",
        )
        .bind(key)
        .bind(operation)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(event)
    }
    /// Retain an independently prepared source; immutable operation identity survives restart.
    pub async fn action_source(
        &self,
        scope: &Value,
        source: &Value,
        prepare: bool,
    ) -> Result<Value> {
        let key = wire::raw(scope)?;
        let operation = source["request"]["operation"]["id"]
            .as_str()
            .ok_or(Error::Invalid)?;
        let raw = wire::raw(source)?;
        let (mut tx, _) = self.locked(&key).await?;
        if prepare {
            sqlx::query("INSERT INTO gate_action_sources(scope,operation,source) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
                .bind(&key).bind(operation).bind(&raw).execute(&mut *tx).await.map_err(unavailable)?;
        }
        let row =
            sqlx::query("SELECT source FROM gate_action_sources WHERE scope=$1 AND operation=$2")
                .bind(key)
                .bind(operation)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?
                .ok_or(Error::Refused)?;
        if row.get::<String, _>("source") != raw {
            return Err(Error::Conflict);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(source.clone())
    }
    /// Exact retained custody for an event; no replacement acknowledgement is synthesized.
    pub async fn action_evidence(&self, scope: &Value, event: &Value) -> Result<Value> {
        let row = sqlx::query(
            "SELECT event,acknowledgement FROM gate_action_outbox WHERE scope=$1 AND sequence=$2",
        )
        .bind(wire::raw(scope)?)
        .bind(event["sequence"].as_i64().ok_or(Error::Invalid)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        if row.get::<String, _>("event") != wire::raw(event)? {
            return Err(Error::Conflict);
        }
        Ok(
            json!({"event":event,"acknowledgement":row.get::<Option<String>,_>("acknowledgement").map(|v|wire::parse(&v)).transpose()?}),
        )
    }
    /// Pin the externally enrolled generation. A changed generation quarantines old storage.
    /// This is deliberately not a restore/reopen operation.
    pub async fn execution_generation(&self, scope: &Value, generation: u64) -> Result<()> {
        if generation == 0 || generation > 9007199254740991 {
            return Err(Error::Invalid);
        }
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        sqlx::query("INSERT INTO gate_execution_generation(scope,generation) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(&key).bind(generation as i64).execute(&mut *tx).await.map_err(unavailable)?;
        let row = sqlx::query("SELECT generation FROM gate_execution_generation WHERE scope=$1")
            .bind(&key)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if row.get::<i64, _>("generation") != generation as i64 {
            return Err(Error::Refused);
        }
        tx.commit().await.map_err(unavailable)
    }
    /// Commit send intent before returning the sole permission. Retry is unresolved, never permission.
    pub async fn action_final(&self, a: &Admission, custody: &Custody) -> Result<Value> {
        current(a)?;
        let r = &a.request;
        let scope = &r["operation"]["scope"];
        let key = wire::raw(scope)?;
        let operation = r["operation"]["id"].as_str().ok_or(Error::Invalid)?;
        wire::scoped(&custody.invocation, scope)?;
        if custody.invocation["scope"] != *scope
            || custody.invocation["kind"] != "invocation"
            || custody.expires_at <= a.now.saturating_add(2)
            || custody.expires_at > a.now.saturating_add(5)
            || r["context"]["recovery"]["revision"] != custody.recovery
        {
            return Err(Error::Refused);
        }
        let (mut tx, head) = self.locked(&key).await?;
        let generation =
            sqlx::query("SELECT generation FROM gate_execution_generation WHERE scope=$1")
                .bind(&key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?
                .ok_or(Error::Refused)?;
        if generation.get::<i64, _>("generation") as u64 != custody.recovery {
            return Err(Error::Refused);
        }
        let row = sqlx::query(
            "SELECT binding,consumption FROM gate_action_claims WHERE scope=$1 AND operation=$2",
        )
        .bind(&key)
        .bind(operation)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        if row.get::<String, _>("binding") != wire::raw(&binding(a))? {
            return Err(Error::Conflict);
        }
        let consumption = wire::parse(
            &row.get::<Option<String>, _>("consumption")
                .ok_or(Error::Refused)?,
        )?;
        let c = &consumption["consumption"]["payload"];
        if c["worker"] != custody.worker
            || c["worker_fence"] != custody.fence
            || c["grant"] != custody.grant
            || consumption["binding"]["grant_event"]["payload"]["expires_at"]
                .as_u64()
                .ok_or(Error::Invalid)?
                <= a.now.saturating_add(2)
            || head.get::<bool, _>("paused")
            || r["context"]["activation"]["revision"] != head.get::<i64, _>("epoch")
            || artifact_set(r)? != head.get::<String, _>("digest")
            || cancelled(&mut tx, &key, r, &a.approval["approval"]).await?
        {
            return Err(Error::Refused);
        }
        if sqlx::query("SELECT 1 FROM gate_action_dispatch WHERE scope=$1 AND operation=$2")
            .bind(&key)
            .bind(operation)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?
            .is_some()
        {
            return Ok(json!({"send_permitted":false,"status":"unresolved"}));
        }
        let pre = &consumption["predispatch"];
        let ack = sqlx::query(
            "SELECT event,acknowledgement FROM gate_action_outbox WHERE scope=$1 AND sequence=$2",
        )
        .bind(&key)
        .bind(pre["sequence"].as_i64().ok_or(Error::Invalid)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if ack.get::<String, _>("event") != wire::raw(pre)? {
            return Err(Error::Conflict);
        }
        let ack = wire::parse(
            &ack.get::<Option<String>, _>("acknowledgement")
                .ok_or(Error::Refused)?,
        )?;
        crate::activation_delivery::acknowledge(pre, &ack)?;
        let mut p = c.clone();
        p.as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("reservations");
        p["kind"] = json!("send-intent");
        p["invocation"] = custody.invocation.clone();
        p["predispatch_ack_digest"] = json!(wire::digest("event-ack", &ack)?);
        p["target"] = r["intent"]["target"].clone();
        p["effect_key"] = json!(operation);
        let event = append(
            &mut tx,
            scope,
            p,
            vec![wire::digest("accountability-event", pre)?],
            a.now,
        )
        .await?;
        sqlx::query("INSERT INTO gate_action_dispatch(scope,operation,admission) VALUES($1,$2,$3)")
            .bind(&key)
            .bind(operation)
            .bind(wire::raw(&event)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(json!({"send_permitted":true,"send_intent":event,"expires_at":custody.expires_at}))
    }
    /// Inspect retained send state without creating send permission.
    pub async fn action_dispatch(&self, scope: &Value, operation: &str) -> Result<Value> {
        let row = sqlx::query(
            "SELECT admission,outcome FROM gate_action_dispatch WHERE scope=$1 AND operation=$2",
        )
        .bind(wire::raw(scope)?)
        .bind(operation)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        match row {
            None => Ok(json!({"send_permitted":false})),
            Some(row) => Ok(json!({"send_permitted":false,
            "send_intent":wire::parse(&row.get::<String,_>("admission"))?,
            "outcome":row.get::<Option<String>,_>("outcome").map(|v|wire::parse(&v)).transpose()?})),
        }
    }
    /// Persist an uncertain outcome; only independent reconciliation may settle its exposure.
    pub async fn action_unresolved(
        &self,
        scope: &Value,
        operation: &str,
        now: u64,
    ) -> Result<Value> {
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let row = sqlx::query(
            "SELECT admission,outcome FROM gate_action_dispatch WHERE scope=$1 AND operation=$2",
        )
        .bind(&key)
        .bind(operation)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        if let Some(old) = row.get::<Option<String>, _>("outcome") {
            return wire::parse(&old);
        }
        let send = wire::parse(&row.get::<String, _>("admission"))?;
        let mut payload = send["payload"].clone();
        let object = payload.as_object_mut().ok_or(Error::Invalid)?;
        for k in [
            "grant",
            "worker",
            "worker_fence",
            "predispatch_ack_digest",
            "target",
        ] {
            object.remove(k);
        }
        payload["kind"] = json!("outcome");
        payload["effect_status"] = json!("unresolved");
        payload["evidence"] = json!([]);
        let event = append(
            &mut tx,
            scope,
            payload,
            vec![wire::digest("accountability-event", &send)?],
            now,
        )
        .await?;
        sqlx::query("UPDATE gate_action_dispatch SET outcome=$3 WHERE scope=$1 AND operation=$2")
            .bind(key)
            .bind(operation)
            .bind(wire::raw(&event)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(event)
    }
}
