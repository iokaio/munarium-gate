// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::activation_delivery as delivery;
impl Store {
    /// Persist the next exact event before sending; an unacknowledged predecessor blocks progress.
    pub async fn delivery_next(
        &self,
        scope: &Value,
        registration: &Value,
        now: u64,
    ) -> Result<Option<Value>> {
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let row = sqlx::query("SELECT o.id,o.record,d.event FROM gate_activation_outbox o LEFT JOIN gate_activation_delivery d ON d.scope=o.scope AND d.id=o.id WHERE o.scope=$1 AND o.phase='applied' AND d.acknowledgement IS NULL ORDER BY o.sequence LIMIT 1")
            .bind(&key).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if let Some(raw) = row.get::<Option<String>, _>("event") {
            let e = wire::parse(&raw)?;
            delivery::registered(&e, registration)?;
            return Ok(Some(e));
        }
        let prior = sqlx::query("SELECT event FROM gate_activation_delivery WHERE scope=$1 ORDER BY sequence DESC LIMIT 1")
            .bind(&key).fetch_optional(&mut *tx).await.map_err(unavailable)?
            .map(|r| wire::parse(&r.get::<String,_>("event"))).transpose()?;
        let e = delivery::event(
            &wire::parse(&row.get::<String, _>("record"))?,
            registration,
            prior.as_ref(),
            now,
        )?;
        sqlx::query(
            "INSERT INTO gate_activation_delivery(scope,id,sequence,event) VALUES($1,$2,$3,$4)",
        )
        .bind(&key)
        .bind(row.get::<String, _>("id"))
        .bind(e["sequence"].as_i64().ok_or(Error::Invalid)?)
        .bind(wire::raw(&e)?)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(Some(e))
    }
    /// Retain only an exact custody receipt, idempotently across concurrent delivery.
    pub async fn delivery_ack(&self, scope: &Value, event: &Value, ack: &Value) -> Result<()> {
        delivery::acknowledge(event, ack)?;
        wire::scoped(event, scope)?;
        let key = wire::raw(scope)?;
        let (mut tx, _) = self.locked(&key).await?;
        let row = sqlx::query(
            "SELECT event,acknowledgement FROM gate_activation_delivery WHERE scope=$1 AND id=$2",
        )
        .bind(&key)
        .bind(
            event["payload"]["receipt"]["transition"]["id"]
                .as_str()
                .ok_or(Error::Invalid)?,
        )
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
        sqlx::query(
            "UPDATE gate_activation_delivery SET acknowledgement=$3 WHERE scope=$1 AND event=$2",
        )
        .bind(key)
        .bind(wire::raw(event)?)
        .bind(raw)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(())
    }
}
