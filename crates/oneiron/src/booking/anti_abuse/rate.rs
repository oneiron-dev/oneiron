use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};

use super::rules::check_slot_list_cache_ttl;
use super::storage::{
    CACHE_BODY_MAX_LEN, QUARANTINE_RATE_DOMAIN, RATE_WINDOW_SECS, decode_row, encode_row,
    engine_failure, rate_counter_key, refused, slot_list_cache_key,
};
use crate::booking::lifecycle::{booking_writer, digest_with, put_meta, read_meta_bytes};
use crate::booking::{BookingError, EventTypeKey};
use crate::{EntityId, Vault};

// -------------------------------------------------------------------------
// Rate counters
// -------------------------------------------------------------------------

/// Outcome of one minute-window counter observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookingRateDecision {
    /// The request consumed one token.
    Allowed,
    /// The window is spent; no token was consumed, so a rejection is free.
    Exceeded { retry_after_secs: u64 },
}

/// One node-local window counter, mirroring `task_verb.rs`: key per
/// (purpose, material), value `{window, count}`, overwritten each window.
pub(super) fn consume_rate_token_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    purpose: &[u8],
    material: &[u8],
    per_minute: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    let window = now_secs / RATE_WINDOW_SECS;
    let key = rate_counter_key(purpose, material);
    let count = match read_meta_bytes(vault, &*wtxn, &key)? {
        Some(raw) => {
            let stored: [u8; 16] = raw
                .as_slice()
                .try_into()
                .map_err(|_| refused("booking anti-abuse rate row is malformed"))?;
            let stored_window = u64::from_le_bytes(stored[..8].try_into().expect("rate window"));
            if stored_window == window {
                u64::from_le_bytes(stored[8..].try_into().expect("rate count"))
            } else {
                0
            }
        }
        None => 0,
    };
    if count >= u64::from(per_minute.get()) {
        return Ok(BookingRateDecision::Exceeded {
            retry_after_secs: RATE_WINDOW_SECS - now_secs % RATE_WINDOW_SECS,
        });
    }
    let mut value = [0_u8; 16];
    value[..8].copy_from_slice(&window.to_le_bytes());
    value[8..].copy_from_slice(&count.saturating_add(1).to_le_bytes());
    put_meta(vault, wtxn, &key, &value)?;
    Ok(BookingRateDecision::Allowed)
}

fn consume_rate_token(
    vault: &Vault,
    purpose: &[u8],
    material: &[u8],
    per_minute: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    booking_writer(vault, |wtxn| {
        consume_rate_token_in_txn(vault, wtxn, purpose, material, per_minute, now_secs)
    })
}

/// Consumes one slot-list token for this IP. Keyed by IP alone: a listing
/// request has not yet asserted an email.
///
/// # Errors
///
/// Storage failures.
pub fn observe_slot_list_request(
    vault: &Vault,
    ip_hash: &[u8; 32],
    per_minute_per_ip: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    consume_rate_token(vault, b"slot-list", ip_hash, per_minute_per_ip, now_secs)
}

/// Consumes the page/scope-wide quarantine budget. This deliberately has no
/// caller identity material: rotating IPs, emails, or submissions cannot open
/// fresh durable-write budgets.
pub fn observe_quarantine_request(
    vault: &Vault,
    page_ref: &EntityId,
    per_minute: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    // This is deliberately page-wide. A page-wide rule governs all events, so
    // a caller-selected event string must not mint a new durable-write bucket.
    let scope_hash = digest_with(QUARANTINE_RATE_DOMAIN, page_ref.as_bytes());
    consume_rate_token(vault, b"quarantine", &scope_hash, per_minute, now_secs)
}

/// Consumes one book token. When an email is available the key combines IP
/// and email, so two people behind one corporate NAT keep independent minute
/// budgets while repeat traffic from one IP+email shares one.
///
/// # Errors
///
/// Storage failures.
pub fn observe_book_request(
    vault: &Vault,
    ip_hash: &[u8; 32],
    email_hash: Option<&[u8; 32]>,
    per_minute_per_ip: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    let material = match email_hash {
        Some(email_hash) => {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(ip_hash);
            combined.extend_from_slice(email_hash);
            combined
        }
        None => ip_hash.to_vec(),
    };
    consume_rate_token(vault, b"book", &material, per_minute_per_ip, now_secs)
}

/// Consumes one hold token for this IP.
///
/// # Errors
///
/// Storage failures.
pub fn observe_hold_request(
    vault: &Vault,
    ip_hash: &[u8; 32],
    per_minute_per_ip: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    consume_rate_token(vault, b"hold", ip_hash, per_minute_per_ip, now_secs)
}

// -------------------------------------------------------------------------
// Slot-list response cache
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SlotListCacheRow {
    stored_at: u64,
    ttl_secs: u64,
    body: Vec<u8>,
}

/// Reads the cached slot-list response for one scope, or `None` when the
/// entry is absent or older than its TTL.
///
/// # Errors
///
/// Storage and decode failures.
pub fn read_slot_list_cache(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
    now_secs: u64,
) -> Result<Option<Vec<u8>>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let Some(raw) = read_meta_bytes(vault, &rtxn, &slot_list_cache_key(page_ref, event_type))?
    else {
        return Ok(None);
    };
    let row: SlotListCacheRow = decode_row(&raw)?;
    if now_secs.saturating_sub(row.stored_at) >= row.ttl_secs {
        return Ok(None);
    }
    Ok(Some(row.body))
}

/// Stores one slot-list response under the booking-only prefix. The TTL must
/// sit inside the ratified 30-60 second window, which rule validation
/// already enforces; this is the same check at the write door.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on an out-of-window TTL or an
/// oversized body; storage failures otherwise.
pub fn write_slot_list_cache(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
    body: &[u8],
    ttl_secs: NonZeroU64,
    now_secs: u64,
) -> Result<(), BookingError> {
    check_slot_list_cache_ttl(ttl_secs.get())?;
    if body.len() > CACHE_BODY_MAX_LEN {
        return Err(refused("slot-list cache body exceeds the 512 KiB bound"));
    }
    let row = SlotListCacheRow {
        stored_at: now_secs,
        ttl_secs: ttl_secs.get(),
        body: body.to_vec(),
    };
    let encoded = encode_row(&row)?;
    booking_writer(vault, |wtxn| {
        put_meta(
            vault,
            wtxn,
            &slot_list_cache_key(page_ref, event_type),
            &encoded,
        )
    })
}
