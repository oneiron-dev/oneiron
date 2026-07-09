use super::API_LEVEL;
use super::check_api_auth;
use super::current_eiri_session_rag_state;
use super::is_agent_visible_entity_type;
use super::validate_eiri_session_id;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::NotificationItem;
use oneiron::ResumeBudget;
use oneiron::ResumeBundle;
use oneiron::SessionContext;
use oneiron::UnprocessedItem;
use oneiron::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) const RESUME_NOTIFICATION_LIMIT: usize = 128;

pub(crate) const RESUME_NOTIFICATION_SCAN_LIMIT: usize = 4096;

/// One-shot read-only companion hydration.
/// POST /api/companion/resume
pub(crate) async fn resume(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<ResumeBundle>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let caller = resume_caller(&headers);
    resume_bundle(&server, &caller).await.map(Json)
}

pub(crate) async fn resume_bundle(
    server: &SyncServer,
    caller: &str,
) -> Result<ResumeBundle, ApiError> {
    Ok(ResumeBundle::new(
        resume_session_context(server, caller).await?,
        pending_notifications(server, caller)?,
        pending_unprocessed_items(server, caller),
        current_resume_budget(server),
    ))
}

pub(crate) async fn resume_session_context(
    server: &SyncServer,
    caller: &str,
) -> Result<SessionContext, ApiError> {
    validate_eiri_session_id(caller, "x-oneiron-caller")?;
    let mut counts = BTreeMap::new();

    for entity_type in u8::MIN..=u8::MAX {
        if !is_agent_visible_entity_type(entity_type) {
            continue;
        }

        let count = server
            .vault
            .count_entities_by_type(entity_type)
            .inspect_err(|e| {
                tracing::error!(error = %e, entity_type, "resume session count scan failed");
            })
            .map_err(|_| ApiError::internal_server_error("resume session count scan failed"))?;

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
                tracing::error!(error = %e, "resume activity summary failed");
            })
            .map_err(|_| ApiError::internal_server_error("resume activity summary failed"))?
    };

    Ok(SessionContext {
        api_version: API_LEVEL.to_owned(),
        counts,
        last_activity,
        rag_state: current_eiri_session_rag_state(&server.vault, caller).await,
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
            RESUME_NOTIFICATION_LIMIT,
            RESUME_NOTIFICATION_SCAN_LIMIT,
        )
        .inspect_err(|e| {
            tracing::error!(error = %e, "resume notification latest scan failed");
        })
        .map_err(|_| ApiError::internal_server_error("resume notification scan failed"))?;

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

pub(crate) fn current_resume_budget(_server: &SyncServer) -> ResumeBudget {
    ResumeBudget::from_meter(0, 0)
}

pub(crate) fn resume_caller(headers: &HeaderMap) -> String {
    headers
        .get("x-oneiron-caller")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .unwrap_or("default")
        .to_owned()
}

pub(crate) fn notification_body_json(raw_body: &[u8]) -> Option<Value> {
    let body: Value = rmp_serde::from_slice(raw_body).ok()?;
    body.as_object()?;
    Some(body)
}

pub(crate) fn notification_scoped_to_caller(body: &Value, caller: &str) -> bool {
    let Some(object) = body.as_object() else {
        return false;
    };

    const SCOPE_KEYS: &[&str] = &[
        "caller",
        "caller_id",
        "callerId",
        "recipient",
        "recipient_id",
        "recipientId",
    ];
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
    let Some(object) = body.as_object() else {
        return false;
    };

    const GLOBAL_KEYS: &[&str] = &["acked", "acknowledged", "surfaced", "seen"];
    if GLOBAL_KEYS
        .iter()
        .any(|key| object.get(*key).and_then(Value::as_bool) == Some(true))
    {
        return true;
    }

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
