use oneiron::booking::SessionKey;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange};

use super::constants::{BOOKER_CONTACT_DOMAIN, SESSION_KEY_DOMAIN};
use super::helpers::{domain_digest, engine_read_error};
use crate::error::ApiError;
use crate::server::SyncServer;

// -------------------------------------------------------------------------
// Subject resolution
// -------------------------------------------------------------------------

/// The visitor session key holds are keyed by.
///
/// Bound to the page as well as to the caller's reference, so one session
/// reference cannot carry a hold across pages.
pub(super) fn session_key(page_ref: EntityId, session_ref: &str) -> SessionKey {
    let mut material = Vec::with_capacity(16 + 1 + session_ref.len());
    material.extend_from_slice(page_ref.as_bytes());
    material.push(0);
    material.extend_from_slice(session_ref.as_bytes());
    SessionKey::derive(&domain_digest(SESSION_KEY_DOMAIN, &material))
}

/// The deterministic contact subject one booker email resolves to.
///
/// Deterministic so a retry converges on the same subject instead of minting
/// a second contact for the same person, and derived server-side so a caller
/// can never name the subject a booking is attributed to.
pub(super) fn booker_contact_ref(email: &str) -> Result<EntityId, ApiError> {
    let normalized = email.trim().to_lowercase();
    let digest = domain_digest(BOOKER_CONTACT_DOMAIN, normalized.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
        .map_err(|_| ApiError::internal_server_error("booker contact subject is not addressable"))
}

/// Resolves the contact subject, materializing it the first time this address
/// books. The subject carries the address itself and nothing else.
pub(super) fn resolve_booker_contact(
    server: &SyncServer,
    email: &str,
    now: u64,
) -> Result<EntityId, ApiError> {
    let contact_ref = booker_contact_ref(email)?;
    let existing = server
        .vault
        .get_entity_type(&contact_ref)
        .map_err(engine_read_error)?;
    if existing.is_none() {
        server
            .vault
            .put_entity(
                &contact_ref,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                email.trim().to_lowercase().as_bytes(),
            )
            .map_err(engine_read_error)?;
    }
    Ok(contact_ref)
}
