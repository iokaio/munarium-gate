// SPDX-License-Identifier: Apache-2.0
//! Immutable activation events and exact custody acknowledgements.
use crate::activation_wire::{self as wire, Error, Result};
use serde_json::{Value, json};

/// Select the one dedicated owner stream from current authenticated Server authority.
pub fn registration(
    state: &Value,
    scope: &Value,
    server: &str,
    service: &str,
    owner: &str,
) -> Result<Value> {
    let policy = &state["artifact"]["bindings"][format!("action-records:{server}")];
    if policy["scope"] != *scope
        || policy["schema_version"] != 1
        || policy["profile"] != "stage2-single-cell-v1"
    {
        return Err(Error::Refused);
    }
    let streams = policy["streams"].as_array().ok_or(Error::Refused)?;
    let mut matches = streams.iter().filter(|s| {
        s["service"] == service
            && s["producer"] == owner
            && s["kinds"] == json!(["activation-applied"])
    });
    let found = matches.next().ok_or(Error::Refused)?;
    if matches.next().is_some() {
        return Err(Error::Refused);
    }
    Ok(json!({"stream":found["stream_id"],"generation":found["generation"]}))
}

/// Materialize one observation; callers persist these bytes before any network send.
pub fn event(
    receipt: &Value,
    registration: &Value,
    prior: Option<&Value>,
    now: u64,
) -> Result<Value> {
    wire::shape(receipt, "activation-receipt")?;
    if receipt["phase"] != "applied" {
        return Err(Error::Refused);
    }
    let scope = &receipt["transition"]["scope"];
    let stream = json!({"scope":scope,"kind":"stream","id":registration["stream"]});
    let (sequence, predecessor) = if let Some(p) = prior {
        if p["stream"] != stream
            || p["source_generation"] != registration["generation"]
            || p["producer"] != receipt["participant"]
        {
            return Err(Error::Conflict);
        }
        (
            p["sequence"]
                .as_u64()
                .ok_or(Error::Invalid)?
                .checked_add(1)
                .ok_or(Error::Invalid)?,
            json!(wire::digest("accountability-event", p)?),
        )
    } else {
        (1, Value::Null)
    };
    let payload = json!({"kind":"activation-applied","receipt":receipt});
    let event = json!({"schema_version":1,"type":"accountability-event","profile":"stage2-single-cell-v1","scope":scope,
        "event_id":format!("{}-{}",receipt["participant"].as_str().ok_or(Error::Invalid)?, &receipt["transition_digest"].as_str().ok_or(Error::Invalid)?[7..]),
        "producer":receipt["participant"],"stream":stream,"source_generation":registration["generation"],"sequence":sequence,"predecessor":predecessor,
        "occurred_at":now,"clock":"bounded-utc-2s","family":"activation","kind":"activation-applied","payload":payload,
        "payload_digest":wire::digest("event-payload",&payload)?,"causal_parents":[]});
    wire::shape(&event, "accountability-event")?;
    Ok(event)
}

/// Refuse changed registration even for an already materialized pending event.
pub fn registered(event: &Value, registration: &Value) -> Result<()> {
    if event["stream"]["id"] != registration["stream"]
        || event["source_generation"] != registration["generation"]
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Validate custody without interpreting an acknowledgement as execution authority.
pub fn acknowledge(event: &Value, ack: &Value) -> Result<()> {
    wire::shape(ack, "event-ack")?;
    wire::scoped(ack, &event["scope"])?;
    if ack["scope"] != event["scope"]
        || ack["event_id"] != event["event_id"]
        || ack["payload_digest"] != event["payload_digest"]
        || ack["event_digest"] != wire::digest("accountability-event", event)?
    {
        return Err(Error::Refused);
    }
    Ok(())
}
