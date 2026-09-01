use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use oneiron::booking::config::{BOOKING_EVENT_TYPE_PREDICATE, decode_event_type_claim_value};
use oneiron::booking::{BookingError, EventTypeConfig};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::{ClaimLifecycleStatus, ClaimSubject, EntityId, Vault};

use super::constants::{PAGE_TOKEN_BYTES, PAGE_TOKEN_DOMAIN, PAGE_TOKEN_PREFIX};
use super::helpers::{booking_error, domain_digest, engine_read_error, hex_lower};
use crate::error::ApiError;
use crate::server::SyncServer;

// -------------------------------------------------------------------------
// Opaque page tokens
// -------------------------------------------------------------------------

/// The opaque public token for one booking page.
///
/// A domain-separated digest, truncated to [`PAGE_TOKEN_BYTES`]. It is a
/// ONE-WAY function of the page subject: the token carries no identifier and
/// no caller can run it backwards, which is what lets the executor accept it
/// from public data without ever accepting an `EntityId`.
#[must_use]
pub(crate) fn booking_page_token(page_ref: EntityId) -> String {
    let digest = domain_digest(PAGE_TOKEN_DOMAIN, page_ref.as_bytes());
    format!(
        "{PAGE_TOKEN_PREFIX}{}",
        hex_lower(&digest[..PAGE_TOKEN_BYTES])
    )
}

/// Resolves an opaque page token to the booking page it names.
///
/// The memo is a node-local shortcut over a deterministic derivation, so a
/// miss means "look again", never "absent": the authoritative answer is always
/// the scan, and the scan only ever names pages the vault already carries a
/// live `booking.event_type` claim for.
pub(crate) fn resolve_booking_page(
    server: &SyncServer,
    page_token: &str,
) -> Result<EntityId, ApiError> {
    validate_page_token_shape(page_token)?;
    if let Some(page_ref) = memoized_page(page_token)
        && page_is_bookable(&server.vault, page_ref)?
    {
        return Ok(page_ref);
    }
    for page_ref in booking_page_candidates(&server.vault)? {
        if booking_page_token(page_ref) == page_token {
            memoize_page(page_token, page_ref);
            return Ok(page_ref);
        }
    }
    Err(ApiError::not_found("booking page", Some(page_token)))
}

fn validate_page_token_shape(page_token: &str) -> Result<(), ApiError> {
    let well_formed = page_token
        .strip_prefix(PAGE_TOKEN_PREFIX)
        .is_some_and(|digest| {
            digest.len() == PAGE_TOKEN_BYTES * 2
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if well_formed {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            format!(
                "page_token must be {PAGE_TOKEN_PREFIX} followed by 32 lowercase hex characters"
            ),
            Some("page_token"),
        ))
    }
}

fn page_token_memo() -> &'static Mutex<HashMap<String, EntityId>> {
    static MEMO: OnceLock<Mutex<HashMap<String, EntityId>>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

fn memoized_page(page_token: &str) -> Option<EntityId> {
    page_token_memo()
        .lock()
        .ok()
        .and_then(|memo| memo.get(page_token).copied())
}

fn memoize_page(page_token: &str, page_ref: EntityId) {
    if let Ok(mut memo) = page_token_memo().lock() {
        memo.insert(page_token.to_owned(), page_ref);
    }
}

/// Whether a page still carries a booking configuration claim.
fn page_is_bookable(vault: &Vault, page_ref: EntityId) -> Result<bool, ApiError> {
    Ok(!page_event_type_configs(vault, page_ref)?.is_empty())
}

/// Every entity carrying a live `booking.event_type` claim.
///
/// The claim family is the definition of a booking page: nothing else makes
/// an entity bookable, so nothing else can answer a page token.
fn booking_page_candidates(vault: &Vault) -> Result<Vec<EntityId>, ApiError> {
    let mut pages: Vec<EntityId> = Vec::new();
    let mut after: Option<EntityId> = None;
    loop {
        let page = vault
            .entities_by_type_page(ENTITY_TYPE_CLAIM, after.as_ref(), 512)
            .map_err(engine_read_error)?;
        if page.is_empty() {
            break;
        }
        after = page.last().copied();
        for claim_id in page {
            let Some(body) = vault.get_claim(&claim_id).map_err(engine_read_error)? else {
                continue;
            };
            if body.predicate != BOOKING_EVENT_TYPE_PREDICATE
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            if let ClaimSubject::Entity(subject) = body.subject
                && !pages.contains(&subject)
            {
                pages.push(subject);
            }
        }
    }
    Ok(pages)
}

/// Every event-type configuration live on one booking page.
pub(super) fn page_event_type_configs(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<EventTypeConfig>, ApiError> {
    page_event_type_configs_engine(vault, page_ref).map_err(booking_error)
}

pub(super) fn page_event_type_configs_engine(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<EventTypeConfig>, BookingError> {
    let claim_ids = vault
        .claims_for_subject(&page_ref)
        .map_err(|_| BookingError::SlotOracle("booking page claim read failed".to_owned()))?;
    let mut configs = Vec::new();
    for claim_id in claim_ids {
        let Ok(Some(body)) = vault.get_claim(&claim_id) else {
            continue;
        };
        if body.predicate != BOOKING_EVENT_TYPE_PREDICATE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.subject != ClaimSubject::Entity(page_ref)
        {
            continue;
        }
        // Past this point the row IS a booking configuration claim, so a
        // malformed body is a typed failure rather than a silent skip.
        let decoded = decode_event_type_claim_value(&body.value)?;
        if decoded.page_ref == page_ref {
            configs.push(decoded.config);
        }
    }
    Ok(configs)
}
