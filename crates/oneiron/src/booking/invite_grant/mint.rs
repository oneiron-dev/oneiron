//! Mints the one standing page invite grant and finds the live one for a page.

use super::codec::{engine_failure, refused};
use super::types::PublishBookingPageGrantRequest;
use crate::Vault;
use crate::booking::constraint::BookingError;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError};
use crate::outbound_grant::{
    BookingPageInviteGrantMintIntent, StandingOutboundGrant, StandingOutboundGrantScope,
    StandingOutboundGrantStatus, standing_outbound_grant_principal_index_entity_id,
    standing_outbound_grant_principal_index_prefix,
};

/// Domain tag for the deterministic page-grant entity id. Deriving the id from
/// the page is what makes a second publish land on
/// [`RecordError::OutboundGrantAlreadyExists`](crate::error::RecordError::OutboundGrantAlreadyExists) instead of on a second live grant.
pub(super) const PAGE_INVITE_GRANT_ID_DOMAIN: &[u8] = b"oneiron.booking.page_invite_grant.v1\0";

/// Mints — or returns — the ONE live invite grant for a published page.
///
/// Idempotent by construction, twice over: the principal index is read before
/// anything is written, and the grant id is DERIVED from the page, so a
/// concurrent second publish loses the `entities.get` race and is answered
/// with the grant that already exists. Equivalent grants never accumulate.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when the grant cannot be read or written;
/// [`BookingError::InvalidConstraint`] when a minted grant cannot be read back.
pub fn mint_publish_page_invite_grant(
    vault: &Vault,
    request: &PublishBookingPageGrantRequest,
) -> Result<StandingOutboundGrant, BookingError> {
    let principal_ref = request.publisher_principal.to_hex();
    if let Some((_, grant)) = live_page_invite_grant(vault, &principal_ref, &request.page_ref)? {
        return Ok(grant);
    }
    let id = page_invite_grant_id(&request.page_ref)?;
    let intent = BookingPageInviteGrantMintIntent {
        page_ref: request.page_ref,
        publisher_principal: request.publisher_principal,
    };
    match vault.mint_booking_page_invite_outbound_grant(&id, &intent, request.issued_at) {
        Ok(grant) => Ok(grant),
        Err(Error::Record(RecordError::OutboundGrantAlreadyExists)) => vault
            .get_standing_outbound_grant(&id)
            .map_err(|error| engine_failure("page invite grant read", error))?
            .ok_or_else(|| refused("the existing booking page invite grant did not read back")),
        Err(error) => Err(engine_failure("page invite grant mint", error)),
    }
}

/// The live `BookingPageInvites` grant this principal holds for `page_ref`.
///
/// Converges on one deterministic grant if several ever coexist, exactly as
/// CAL-04's consent door does.
pub(super) fn live_page_invite_grant(
    vault: &Vault,
    principal_ref: &str,
    page_ref: &EntityId,
) -> Result<Option<(EntityId, StandingOutboundGrant)>, BookingError> {
    // The index scan closes its read transaction before any grant is read:
    // LMDB gives a thread one read transaction at a time, and each grant read
    // opens its own.
    let ids = {
        let prefix = standing_outbound_grant_principal_index_prefix(principal_ref)
            .map_err(|error| engine_failure("grant principal prefix", error))?;
        let rtxn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| engine_failure("read transaction", error))?;
        let mut ids = Vec::new();
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, &prefix)
            .map_err(|error| engine_failure("grant principal scan", error))?
        {
            let (key, _) = entry.map_err(|error| engine_failure("grant principal scan", error))?;
            ids.push(
                standing_outbound_grant_principal_index_entity_id(&key, principal_ref)
                    .map_err(|error| engine_failure("grant principal key", error))?,
            );
        }
        ids
    };
    let wanted = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: *page_ref,
    };
    let mut matched: Option<(EntityId, StandingOutboundGrant)> = None;
    for id in ids {
        let Some(grant) = vault
            .get_standing_outbound_grant(&id)
            .map_err(|error| engine_failure("standing grant read", error))?
        else {
            continue;
        };
        if grant.status != StandingOutboundGrantStatus::Active
            || grant.revoked_at.is_some()
            || grant.scope != wanted
        {
            continue;
        }
        if matched
            .as_ref()
            .is_none_or(|(current, _)| id.as_bytes() < current.as_bytes())
        {
            matched = Some((id, grant));
        }
    }
    Ok(matched)
}

/// The deterministic grant id one page's invite grant lives at.
pub(super) fn page_invite_grant_id(page_ref: &EntityId) -> Result<EntityId, BookingError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PAGE_INVITE_GRANT_ID_DOMAIN);
    hasher.update(page_ref.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|error| engine_failure("page invite grant id", error))
}
