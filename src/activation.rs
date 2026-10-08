// SPDX-License-Identifier: Apache-2.0
//! Gate-owned PostgreSQL activation barrier. No action or target effect is admitted here.
use crate::activation_wire::{self as wire, Authority, Error, Result};
use serde_json::{Value, json};
pub(crate) mod sqlx {
    pub use sqlx_core::{
        Error, query::query, raw_sql::raw_sql, row::Row, transaction::Transaction,
    };
    pub use sqlx_postgres::{PgPool, Postgres};
    pub mod postgres {
        pub use sqlx_postgres::{PgPoolOptions, PgRow};
    }
}
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::time::Duration;
mod delivery;
pub(crate) fn unavailable(_: sqlx::Error) -> Error {
    Error::Unavailable
}
/// Independently authenticated current participant evidence, not a request DTO.
pub struct Evidence {
    /// Applied receipts obtained directly from Registry, Server and Warden.
    pub receipts: Vec<Value>,
    /// Current heads obtained directly from those same participants.
    pub heads: Vec<Value>,
}
/// Cloneable pool; every mutation serializes on the qualified cell row.
#[derive(Clone)]
pub struct Store {
    pub(crate) pool: PgPool,
}
impl Store {
    /// Connect to an operator-owned database and apply additive owner tables.
    pub async fn open(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(3))
            .connect(url)
            .await
            .map_err(unavailable)?;
        let mut tx = pool.begin().await.map_err(unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(723028241)")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(include_str!("../migrations/0001_activation.sql"))
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(include_str!("../migrations/0002_activation_delivery.sql"))
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(include_str!("../migrations/0003_action_journal.sql"))
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(include_str!("../migrations/0004_final_send.sql"))
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(include_str!("../migrations/0005_reconciliation.sql"))
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(Self { pool })
    }
    /// Enroll once. Later requests must retain the original enrollment, not reset the head.
    pub async fn initialize(&self, scope: &Value, epoch: u64, digest: &str) -> Result<()> {
        wire::initial(scope, epoch, digest)?;
        let key = wire::raw(scope)?;
        sqlx::query("INSERT INTO gate_activation_cells(scope,initial_epoch,initial_digest,epoch,digest,paused) VALUES($1,$2,$3,$2,$3,TRUE) ON CONFLICT DO NOTHING")
            .bind(&key).bind(epoch as i64).bind(digest).execute(&self.pool).await.map_err(unavailable)?;
        let row = sqlx::query(
            "SELECT initial_epoch,initial_digest FROM gate_activation_cells WHERE scope=$1",
        )
        .bind(key)
        .fetch_one(&self.pool)
        .await
        .map_err(unavailable)?;
        if row.get::<i64, _>("initial_epoch") != epoch as i64
            || row.get::<String, _>("initial_digest") != digest
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) async fn locked(
        &self,
        key: &str,
    ) -> Result<(sqlx::Transaction<'_, sqlx::Postgres>, sqlx::postgres::PgRow)> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SET LOCAL lock_timeout='2s'")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let row = sqlx::query("SELECT * FROM gate_activation_cells WHERE scope=$1 FOR UPDATE")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Refused)?;
        Ok((tx, row))
    }
    /// Commit pause and its outbox before returning; only one pending transition can own it.
    pub async fn pause(&self, auth: &Authority, t: &Value) -> Result<Value> {
        wire::validate(auth, t)?;
        let key = wire::raw(&auth.scope)?;
        let id = t["transition"]["id"].as_str().ok_or(Error::Invalid)?;
        let raw = wire::raw(t)?;
        let (mut tx, head) = self.locked(&key).await?;
        let old = sqlx::query(
            "SELECT record,pause FROM gate_activation_transitions WHERE scope=$1 AND id=$2",
        )
        .bind(&key)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        if let Some(old) = old {
            if old.get::<String, _>("record") != raw
                || head.get::<Option<String>, _>("transition_id").as_deref() != Some(id)
            {
                return Err(Error::Conflict);
            }
            return wire::parse(&old.get::<String, _>("pause"));
        }
        if head.get::<bool, _>("paused") && head.get::<Option<String>, _>("transition_id").is_some()
            || t["prior_epoch"] != head.get::<i64, _>("epoch")
            || t["prior_artifact_set_digest"] != head.get::<String, _>("digest")
        {
            return Err(Error::Conflict);
        }
        let receipt = wire::receipt(t, "gate", "paused")?;
        let encoded = wire::raw(&receipt)?;
        sqlx::query(
            "INSERT INTO gate_activation_transitions(scope,id,record,pause) VALUES($1,$2,$3,$4)",
        )
        .bind(&key)
        .bind(id)
        .bind(&raw)
        .bind(&encoded)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query("UPDATE gate_activation_cells SET paused=TRUE,transition_id=$2 WHERE scope=$1")
            .bind(&key)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        outbox(&mut tx, &key, id, "paused", &encoded).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(receipt)
    }
    /// Install the matching epoch while paused, retaining the original applied receipt.
    pub async fn apply(&self, auth: &Authority, t: &Value) -> Result<Value> {
        wire::validate(auth, t)?;
        let key = wire::raw(&auth.scope)?;
        let id = t["transition"]["id"].as_str().ok_or(Error::Invalid)?;
        let (mut tx, head) = self.locked(&key).await?;
        let old = sqlx::query(
            "SELECT record,applied FROM gate_activation_transitions WHERE scope=$1 AND id=$2",
        )
        .bind(&key)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        if old.get::<String, _>("record") != wire::raw(t)? {
            return Err(Error::Conflict);
        }
        if let Some(r) = old.get::<Option<String>, _>("applied") {
            return wire::parse(&r);
        }
        if !head.get::<bool, _>("paused")
            || head.get::<Option<String>, _>("transition_id").as_deref() != Some(id)
            || t["prior_epoch"] != head.get::<i64, _>("epoch")
            || t["prior_artifact_set_digest"] != head.get::<String, _>("digest")
        {
            return Err(Error::Conflict);
        }
        let receipt = wire::receipt(t, "gate", "applied")?;
        let encoded = wire::raw(&receipt)?;
        sqlx::query("UPDATE gate_activation_cells SET epoch=$2,digest=$3 WHERE scope=$1")
            .bind(&key)
            .bind(t["successor_epoch"].as_i64().ok_or(Error::Invalid)?)
            .bind(t["artifact_set_digest"].as_str().ok_or(Error::Invalid)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("UPDATE gate_activation_transitions SET applied=$3 WHERE scope=$1 AND id=$2")
            .bind(&key)
            .bind(id)
            .bind(&encoded)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        outbox(&mut tx, &key, id, "applied", &encoded).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(receipt)
    }
    /// Resume only with exact complete caller data and independently fetched current evidence.
    pub async fn resume(
        &self,
        auth: &Authority,
        completion: &Value,
        evidence: &Evidence,
    ) -> Result<Value> {
        let t = &completion["transition"];
        wire::validate(auth, t)?;
        if completion.as_object().is_none_or(|m| m.len() != 3) {
            return Err(Error::Invalid);
        }
        let supplied = completion["receipts"].as_array().ok_or(Error::Invalid)?;
        if supplied.len() != 4 || evidence.receipts.len() != 3 || evidence.heads.len() != 3 {
            return Err(Error::Refused);
        }
        for owner in ["registry", "server", "warden"] {
            let r = one(&evidence.receipts, owner)?;
            wire::check_receipt(t, r, owner, "applied")?;
            if one(supplied, owner)? != r {
                return Err(Error::Refused);
            }
            wire::check_head(t, one(&evidence.heads, owner)?, owner)?;
        }
        let key = wire::raw(&auth.scope)?;
        let id = t["transition"]["id"].as_str().ok_or(Error::Invalid)?;
        let (mut tx, head) = self.locked(&key).await?;
        let old = sqlx::query(
            "SELECT record,pause,applied FROM gate_activation_transitions WHERE scope=$1 AND id=$2",
        )
        .bind(&key)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        if old.get::<String, _>("record") != wire::raw(t)?
            || head.get::<Option<String>, _>("transition_id").as_deref() != Some(id)
            || t["successor_epoch"] != head.get::<i64, _>("epoch")
            || t["artifact_set_digest"] != head.get::<String, _>("digest")
            || wire::parse(&old.get::<String, _>("pause"))? != completion["pause"]
            || wire::parse(
                &old.get::<Option<String>, _>("applied")
                    .ok_or(Error::Refused)?,
            )? != *one(supplied, "gate")?
        {
            return Err(Error::Refused);
        }
        let reply = json!({"transition_digest":wire::digest("activation",t)?,"resumed":true,"execution_enabled":false});
        sqlx::query("UPDATE gate_activation_cells SET paused=FALSE WHERE scope=$1")
            .bind(&key)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("UPDATE gate_activation_transitions SET resumed=TRUE WHERE scope=$1 AND id=$2")
            .bind(&key)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        outbox(&mut tx, &key, id, "resumed", &wire::raw(&reply)?).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(reply)
    }
    /// Historical receipt lookup has no admission effect.
    pub async fn lookup(&self, scope: &Value, id: &str, paused: bool) -> Result<Value> {
        let row = sqlx::query(
            "SELECT pause,applied FROM gate_activation_transitions WHERE scope=$1 AND id=$2",
        )
        .bind(wire::raw(scope)?)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        let raw: Option<String> = row.get(if paused { "pause" } else { "applied" });
        wire::parse(&raw.ok_or(Error::Refused)?)
    }
    /// Barrier state is separate from execution availability.
    pub async fn head(&self, scope: &Value) -> Result<Value> {
        let r = sqlx::query(
            "SELECT epoch,digest,paused,transition_id FROM gate_activation_cells WHERE scope=$1",
        )
        .bind(wire::raw(scope)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Refused)?;
        Ok(
            json!({"scope":scope,"participant":"gate","epoch":r.get::<i64,_>("epoch"),"artifact_set_digest":r.get::<String,_>("digest"),
            "paused":r.get::<bool,_>("paused"),"transition_id":r.get::<Option<String>,_>("transition_id"),"execution_enabled":false}),
        )
    }
    /// Retained owner outbox; delivery is a subsequent integration obligation.
    pub async fn pending(&self, scope: &Value) -> Result<Vec<Value>> {
        sqlx::query("SELECT phase,record FROM gate_activation_outbox WHERE scope=$1 ORDER BY sequence")
            .bind(wire::raw(scope)?).fetch_all(&self.pool).await.map_err(unavailable)?.iter()
            .map(|r|Ok(json!({"phase":r.get::<String,_>("phase"),"record":wire::parse(&r.get::<String,_>("record"))?}))).collect()
    }
}
fn one<'a>(items: &'a [Value], owner: &str) -> Result<&'a Value> {
    let mut found = items.iter().filter(|r| r["participant"] == owner);
    let first = found.next().ok_or(Error::Refused)?;
    if found.next().is_some() {
        return Err(Error::Refused);
    }
    Ok(first)
}
async fn outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &str,
    id: &str,
    phase: &str,
    raw: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO gate_activation_outbox(scope,id,phase,record) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(scope).bind(id).bind(phase).bind(raw).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
