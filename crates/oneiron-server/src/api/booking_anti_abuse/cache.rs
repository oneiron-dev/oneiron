//! Slot-list response cache helpers.

use oneiron::EntityId;
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    applicable_booking_anti_abuse_rules, read_slot_list_cache, slot_list_rate_knobs,
    write_slot_list_cache,
};

use super::support::{engine_error, now_secs};
use crate::error::ApiError;
use crate::server::SyncServer;

/// A fresh cached slot-list body for one scope, if one is stored. Handlers
/// consult this after `enforce_slot_list` reports `Continue`.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) fn cached_slot_list_body(
    server: &SyncServer,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
) -> std::result::Result<Option<Vec<u8>>, ApiError> {
    read_slot_list_cache(&server.vault, page_ref, event_type, now_secs()?).map_err(engine_error)
}

/// Stores one slot-list response under the governing rule's cache TTL.
/// Returns `false` when no slot-list rule is seeded for the scope — nothing
/// is cached rather than an invented TTL.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) fn remember_slot_list_body(
    server: &SyncServer,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
    body: &[u8],
) -> std::result::Result<bool, ApiError> {
    let rows = applicable_booking_anti_abuse_rules(&server.vault, page_ref, &event_type.cloned())
        .map_err(engine_error)?;
    let Some((_, cache_ttl_secs)) = slot_list_rate_knobs(&rows, page_ref, &event_type.cloned())
    else {
        return Ok(false);
    };
    write_slot_list_cache(
        &server.vault,
        page_ref,
        event_type,
        body,
        cache_ttl_secs,
        now_secs()?,
    )
    .map_err(engine_error)?;
    Ok(true)
}
