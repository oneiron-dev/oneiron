//! Session prefix material: entity counts, latest activity, pending notifications, unprocessed work, token meter.

use super::super::API_LEVEL;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::HydrationBudget;
use oneiron::NotificationItem;
use oneiron::SessionContext;
use oneiron::UnprocessedItem;
use oneiron::context_board::caller_marker_contains;
use oneiron::context_board::notification_body_json;
use oneiron::context_board::notification_scoped_to_caller;
use oneiron::registry::ENTITY_TYPE_NOTIFICATION;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const PREFIX_NOTIFICATION_LIMIT: usize = 128;

/// Timeline rows one notification page scans. A page only paces the walk,
/// which goes on until the caller's page fills or history ends (FIX 8144).
pub(crate) const PREFIX_NOTIFICATION_SCAN_PAGE: usize = 4096;

/// The session prefix every caller reads: no count and no activity date. A
/// count may count only rows its reader's key reads, and the vault's counts
/// and dates do not, so no row a key cannot read moves it (F16).
pub(crate) fn empty_session_prefix() -> SessionContext {
    SessionContext {
        api_version: API_LEVEL.to_owned(),
        counts: BTreeMap::new(),
        last_activity: None,
    }
}

/// The caller's pending notifications: those `read`, its own read, reads,
/// whose recipient markers name it. A recipient marker targets delivery; it
/// never grants a read the caller does not hold. Each body is the one the
/// read admits, in the snapshot that admits it. The newest-first walk pages
/// on until [`PREFIX_NOTIFICATION_LIMIT`] rows are admitted or history ends,
/// so a row the caller cannot read, or that is another's or already
/// surfaced, never spends the caller's page (FIX 8144).
pub(crate) fn pending_notifications(
    server: &SyncServer,
    read: &oneiron::claim::ScopedRead<'_>,
    caller: &str,
) -> Result<Vec<NotificationItem>, ApiError> {
    let mut notifications = Vec::new();
    let mut after = None;
    loop {
        let (rows, next) = server
            .vault
            .latest_entity_bodies_by_type_page(
                ENTITY_TYPE_NOTIFICATION,
                after,
                PREFIX_NOTIFICATION_SCAN_PAGE,
            )
            .inspect_err(|e| {
                tracing::error!(error = %e, "pending notification latest scan failed");
            })
            .map_err(|_| ApiError::internal_server_error("pending notification scan failed"))?;
        let ids: Vec<_> = rows.into_iter().map(|(id, _, _)| id).collect();
        let admitted = read
            .get_entities_parts_with_receipt(&ids, None)
            .inspect_err(|e| {
                tracing::error!(kind = ?e.kind(), "pending notification admission failed");
            })
            .map_err(|_| ApiError::internal_server_error("pending notification scan failed"))?
            .value;
        for (id, parts) in ids.into_iter().zip(admitted) {
            let Some((entity_type, learned_at, raw_body)) = parts else {
                continue;
            };
            if entity_type != ENTITY_TYPE_NOTIFICATION {
                continue;
            }
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
            if notifications.len() >= PREFIX_NOTIFICATION_LIMIT {
                return Ok(notifications);
            }
        }
        match next {
            Some(next) => after = Some(next),
            None => return Ok(notifications),
        }
    }
}

/// The caller's unprocessed items, as its own read admits them (FIX 7740):
/// see [`oneiron::context_board::unprocessed_items`].
pub(crate) fn pending_unprocessed_items(
    read: &oneiron::claim::ScopedRead<'_>,
) -> Result<Vec<UnprocessedItem>, ApiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    oneiron::context_board::unprocessed_items(read, now)
        .inspect_err(|e| {
            tracing::error!(kind = ?e.kind(), "pending unprocessed scan failed");
        })
        .map_err(|_| ApiError::internal_server_error("pending unprocessed scan failed"))
}

pub(crate) fn current_hydration_budget(_server: &SyncServer) -> HydrationBudget {
    HydrationBudget::from_meter(0, 0)
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
