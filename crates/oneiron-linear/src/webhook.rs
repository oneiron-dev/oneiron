//! Normalizes one verified Linear webhook delivery for the engine (OF-427).
//!
//! The host verifies the `Linear-Signature` HMAC over the raw body before
//! this reads a byte of it. An `Issue` update of the configured team becomes
//! the same [`oneiron::LinearIssueChange`] a scheduled pull builds, through
//! the poller's own field mapping and its fail-closed checks, under the
//! delivery's id as its event id. Every other type or action, and an issue of
//! another team, is carried as ignored. Nothing here writes.

use oneiron::LinearSyncResult;
use oneiron::linear_sync::{
    LINEAR_FIELD_ASSIGNEE_REF, LINEAR_FIELD_DESCRIPTION, LINEAR_FIELD_PRIORITY,
    LINEAR_FIELD_STATUS, LINEAR_FIELD_TITLE, LinearExternalActor, LinearWebhookEvent,
    LinearWebhookKind,
};
use serde_json::{Map, Value};

use crate::invalid;
use crate::source::LinearTrackerConfig;

/// Domain of a delivery body's digest.
const BODY_DIGEST_DOMAIN: &[u8] = b"oneiron:linear-webhook-body:v1";

/// The mirrored field each `updatedFrom` key names.
fn mirrored_field(key: &str) -> Option<&'static str> {
    Some(match key {
        "title" => LINEAR_FIELD_TITLE,
        "description" => LINEAR_FIELD_DESCRIPTION,
        "priority" => LINEAR_FIELD_PRIORITY,
        "assigneeId" | "assignee" => LINEAR_FIELD_ASSIGNEE_REF,
        "stateId" | "state" => LINEAR_FIELD_STATUS,
        _ => return None,
    })
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// The nested `{ id }` object the poller's mapping reads for `nested`, from
/// the nested object when the payload has one, else from its flat `flat` id.
/// Absent both, the field stays absent and the mapping refuses it.
fn nest(data: &mut Map<String, Value>, nested: &str, flat: &str) {
    if data.contains_key(nested) {
        return;
    }
    let Some(id) = data.get(flat).cloned() else {
        return;
    };
    let value = if id.is_null() {
        Value::Null
    } else {
        Value::Object(Map::from_iter([("id".to_owned(), id)]))
    };
    data.insert(nested.to_owned(), value);
}

/// The issue's team id, nested or flat.
fn team_of(data: &Map<String, Value>) -> Option<&str> {
    data.get("team")
        .and_then(|team| team.get("id"))
        .or_else(|| data.get("teamId"))
        .and_then(Value::as_str)
}

/// Normalizes one verified delivery of `body` under `delivery_id`.
///
/// # Errors
/// A transport error for a body that is not a Linear webhook, or an `Issue`
/// update of the configured team that the tracker mapping refuses.
pub fn normalize_issue_webhook(
    body: &[u8],
    delivery_id: &str,
    config: &LinearTrackerConfig,
) -> LinearSyncResult<LinearWebhookEvent> {
    if delivery_id.trim().is_empty() {
        return Err(invalid("Linear webhook delivery id is blank"));
    }
    let payload: Value =
        serde_json::from_slice(body).map_err(|_| invalid("Linear webhook body is not JSON"))?;
    let type_name = text(&payload, "type").ok_or_else(|| invalid("Linear webhook has no type"))?;
    let action = text(&payload, "action").ok_or_else(|| invalid("Linear webhook has no action"))?;
    let mut kind = LinearWebhookKind::Ignored {
        type_name: type_name.clone(),
        action: action.clone(),
    };
    if type_name == "Issue" && action == "update" {
        let mut data = payload
            .get("data")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| invalid("Linear issue webhook has no data"))?;
        if team_of(&data) == Some(config.team_id.as_str()) {
            nest(&mut data, "team", "teamId");
            nest(&mut data, "state", "stateId");
            nest(&mut data, "assignee", "assigneeId");
            let mut change = config.issue(&Value::Object(data))?;
            change.event_id = delivery_id.to_owned();
            kind = LinearWebhookKind::Issue(change);
        }
    }
    let actor = payload.get("actor").and_then(|actor| {
        Some(LinearExternalActor {
            id: text(actor, "id")?,
            kind: text(actor, "type").unwrap_or_else(|| "unknown".to_owned()),
            name: text(actor, "name"),
        })
    });
    let mut changed_fields: Vec<String> = payload
        .get("updatedFrom")
        .and_then(Value::as_object)
        .map_or_else(Vec::new, |from| {
            from.keys()
                .filter_map(|key| mirrored_field(key.as_str()))
                .map(str::to_owned)
                .collect()
        });
    changed_fields.sort();
    changed_fields.dedup();
    let mut digest = blake3::Hasher::new();
    digest.update(BODY_DIGEST_DOMAIN);
    digest.update(body);
    Ok(LinearWebhookEvent {
        delivery_id: delivery_id.to_owned(),
        kind,
        actor,
        webhook_id: text(&payload, "webhookId"),
        organization_id: text(&payload, "organizationId"),
        webhook_timestamp_ms: payload.get("webhookTimestamp").and_then(Value::as_u64),
        changed_fields,
        body_digest: *digest.finalize().as_bytes(),
    })
}
