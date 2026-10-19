use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use oneiron::booking::config::{BOOKING_EVENT_TYPE_PREDICATE, decode_event_type_claim_value};
use oneiron::booking::{BookingError, EventTypeConfig};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::{ClaimLifecycleStatus, ClaimSubject, EntityId, Vault};

use super::constants::{PAGE_TOKEN_BYTES, PAGE_TOKEN_PREFIX};
use super::helpers::{booking_error, engine_read_error};
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
    oneiron::booking::PublicBookingPageToken::for_page(page_ref).0
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

/// [`resolve_booking_page`], beside the rows it resolved the page from
/// (`vault.booking.page_token`'s list), kept from those same reads: the page
/// itself and each live `booking.event_type` claim that makes it bookable.
/// On a memo hit those are the claims the bookability check decoded; on a
/// scan, the live claims the scan found naming the page. Never a later
/// re-read, and never the page ref alone.
pub(crate) fn resolve_booking_page_listing(
    server: &SyncServer,
    page_token: &str,
) -> Result<(EntityId, Vec<EntityId>), ApiError> {
    validate_page_token_shape(page_token)?;
    if let Some(page_ref) = memoized_page(page_token) {
        let claims = page_event_type_claim_ids(&server.vault, page_ref).map_err(booking_error)?;
        if !claims.is_empty() {
            return Ok((page_ref, std::iter::once(page_ref).chain(claims).collect()));
        }
    }
    for (page_ref, claims) in booking_page_candidate_claims(&server.vault)? {
        if booking_page_token(page_ref) == page_token {
            memoize_page(page_token, page_ref);
            return Ok((page_ref, std::iter::once(page_ref).chain(claims).collect()));
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

/// [`booking_page_candidates`], each page beside the live
/// `booking.event_type` claims the scan found naming it, in scan order.
fn booking_page_candidate_claims(
    vault: &Vault,
) -> Result<Vec<(EntityId, Vec<EntityId>)>, ApiError> {
    let mut pages: Vec<(EntityId, Vec<EntityId>)> = Vec::new();
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
            if let ClaimSubject::Entity(subject) = body.subject {
                match pages.iter_mut().find(|(known, _)| *known == subject) {
                    Some((_, claims)) => claims.push(claim_id),
                    None => pages.push((subject, vec![claim_id])),
                }
            }
        }
    }
    Ok(pages)
}

/// The live `booking.event_type` claims [`page_event_type_configs_engine`]
/// decodes one booking page's configurations from, by id, read as it reads
/// them.
fn page_event_type_claim_ids(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<EntityId>, BookingError> {
    let claim_ids = vault
        .claims_for_subject(&page_ref)
        .map_err(|_| BookingError::SlotOracle("booking page claim read failed".to_owned()))?;
    let mut live = Vec::new();
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
        if decode_event_type_claim_value(&body.value)?.page_ref == page_ref {
            live.push(claim_id);
        }
    }
    Ok(live)
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
    Ok(page_event_type_configs_listed(vault, page_ref)?
        .into_iter()
        .map(|(config, _)| config)
        .collect())
}

/// [`page_event_type_configs_engine`], each configuration beside the live
/// `booking.event_type` claim it was decoded from (FIX 4777).
pub(super) fn page_event_type_configs_listed(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<(EventTypeConfig, EntityId)>, BookingError> {
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
            configs.push((decoded.config, claim_id));
        }
    }
    Ok(configs)
}
