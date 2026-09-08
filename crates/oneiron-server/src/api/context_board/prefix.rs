//! Session prefix material: entity counts, latest activity, pending notifications, unprocessed work, token meter.

use super::super::API_LEVEL;
use super::super::is_agent_visible_entity_type;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::HydrationBudget;
use oneiron::NotificationItem;
use oneiron::SessionContext;
use oneiron::UnprocessedItem;
use oneiron::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const PREFIX_NOTIFICATION_LIMIT: usize = 128;

pub(crate) const PREFIX_NOTIFICATION_SCAN_LIMIT: usize = 4096;

pub(crate) async fn session_prefix(server: &SyncServer) -> Result<SessionContext, ApiError> {
    let mut counts = BTreeMap::new();

    for entity_type in u8::MIN..=u8::MAX {
        if !is_agent_visible_entity_type(entity_type) {
            continue;
        }

        let count = server
            .vault
            .count_entities_by_type(entity_type)
            .inspect_err(|e| {
                tracing::error!(error = %e, entity_type, "session prefix count scan failed");
            })
            .map_err(|_| ApiError::internal_server_error("session prefix count scan failed"))?;

        if count == 0 {
            continue;
        }

        counts.insert(entity_type.to_string(), count);
    }

    let last_activity = if counts.is_empty() {
        None
    } else {
        server
            .vault
            .latest_learned_at_excluding_entity_types(&[ENTITY_TYPE_POLICY_MANIFEST])
            .inspect_err(|e| {
                tracing::error!(error = %e, "session prefix activity summary failed");
            })
            .map_err(|_| {
                ApiError::internal_server_error("session prefix activity summary failed")
            })?
    };

    Ok(SessionContext {
        api_version: API_LEVEL.to_owned(),
        counts,
        last_activity,
    })
}

pub(crate) fn pending_notifications(
    server: &SyncServer,
    caller: &str,
) -> Result<Vec<NotificationItem>, ApiError> {
    let mut notifications = Vec::new();

    let rows = server
        .vault
        .latest_entity_bodies_by_type(
            ENTITY_TYPE_NOTIFICATION,
            PREFIX_NOTIFICATION_LIMIT,
            PREFIX_NOTIFICATION_SCAN_LIMIT,
        )
        .inspect_err(|e| {
            tracing::error!(error = %e, "pending notification latest scan failed");
        })
        .map_err(|_| ApiError::internal_server_error("pending notification scan failed"))?;

    for (id, learned_at, raw_body) in rows {
        let Some(body) = notification_body_json(&raw_body) else {
            continue;
        };
        if !notification_scoped_to_caller(&body, caller) {
            continue;
        }
        if notification_already_surfaced(&body, caller) {
            continue;
        }
        notifications.push(NotificationItem {
            id: id.to_hex(),
            learned_at,
            body,
        });
    }

    Ok(notifications)
}

pub(crate) fn pending_unprocessed_items(
    _server: &SyncServer,
    _caller: &str,
) -> Vec<UnprocessedItem> {
    Vec::new()
}

pub(crate) fn current_hydration_budget(_server: &SyncServer) -> HydrationBudget {
    HydrationBudget::from_meter(0, 0)
}

pub(crate) fn notification_body_json(raw_body: &[u8]) -> Option<Value> {
    let body: Value = rmp_serde::from_slice(raw_body).ok()?;
    body.as_object()?;
    Some(body)
}

pub(crate) fn notification_scoped_to_caller(body: &Value, caller: &str) -> bool {
    const SCOPE_KEYS: &[&str] = &[
        "caller",
        "caller_id",
        "callerId",
        "recipient",
        "recipient_id",
        "recipientId",
    ];

    let Some(object) = body.as_object() else {
        return false;
    };

    for key in SCOPE_KEYS {
        if let Some(value) = object.get(*key)
            && !caller_marker_contains(Some(value), caller)
        {
            return false;
        }
    }
    true
}

pub(crate) fn notification_already_surfaced(body: &Value, caller: &str) -> bool {
    const GLOBAL_KEYS: &[&str] = &["acked", "acknowledged", "surfaced", "seen"];
    const CALLER_KEYS: &[&str] = &[
        "acked_by",
        "ackedBy",
        "acknowledged_by",
        "acknowledgedBy",
        "surfaced_by",
        "surfacedBy",
        "seen_by",
        "seenBy",
    ];

    let Some(object) = body.as_object() else {
        return false;
    };

    if GLOBAL_KEYS
        .iter()
        .any(|key| object.get(*key).and_then(Value::as_bool) == Some(true))
    {
        return true;
    }

    CALLER_KEYS
        .iter()
        .any(|key| caller_marker_contains(object.get(*key), caller))
}

pub(crate) fn caller_marker_contains(value: Option<&Value>, caller: &str) -> bool {
    match value {
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(caller)),
        Some(Value::Object(map)) => map.get(caller).and_then(Value::as_bool) == Some(true),
        Some(Value::String(item)) => item == caller,
        _ => false,
    }
}
