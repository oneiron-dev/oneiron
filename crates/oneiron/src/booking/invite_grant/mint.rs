//! Mints the one standing page invite grant and finds the live one for a page.

use super::codec::{engine_failure, refused};
use super::types::PublishBookingPageGrantRequest;
use crate::Vault;
use crate::booking::constraint::BookingError;
use crate::consent::{DerivedGrantOrigin, DerivedGrantSetting};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, standing_outbound_grant_in_txn,
    standing_outbound_grants_for_principal_in_txn,
};

/// Domain tag for the deterministic page-grant id. Deriving the id from the
/// page is what makes a second publish find the grant the first one minted
/// instead of minting a second live grant.
pub(super) const PAGE_INVITE_GRANT_ID_DOMAIN: &[u8] = b"oneiron.booking.page_invite_grant.v1\0";

/// Mints — or returns — the ONE invite grant for a published page.
///
/// Idempotent by construction: the grant id is DERIVED from the page, and a
/// page that already holds a grant under that id, live or revoked, is
/// answered with it. Equivalent grants never accumulate, and a grant the
/// owner revoked stays revoked. The grant carries out the page's
/// publication, whose indexed claim its receipt names when one is indexed,
/// else the page itself.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when the grant cannot be read or written;
/// [`BookingError::InvalidConstraint`] when the vault records no owner to
/// stamp it.
pub fn mint_publish_page_invite_grant(
    vault: &Vault,
    request: &PublishBookingPageGrantRequest,
) -> Result<StandingOutboundGrant, BookingError> {
    let principal_ref = request.publisher_principal.to_hex();
    if let Some((_, grant)) = live_page_invite_grant(vault, &principal_ref, &request.page_ref)? {
        return Ok(grant);
    }
    let id = page_invite_grant_id(&request.page_ref)?;
    vault
        .with_write_txn_grouped(|txn| {
            if let Some(grant) = standing_outbound_grant_in_txn(&vault.store, txn, &id)? {
                return Ok(Some(grant));
            }
            let setting = crate::booking::publication::publication_setting_in_txn(
                vault,
                txn,
                request.page_ref,
            )?
            .unwrap_or_else(|| DerivedGrantSetting {
                receipt_ref: format!("page:{}", request.page_ref.to_hex()),
                setter: None,
            });
            mint_derived_page_invite_grant_in_txn(
                vault,
                txn,
                id,
                request.page_ref,
                request.publisher_principal,
                &setting,
            )
        })
        .map_err(|error| engine_failure("page invite grant mint", error))?
        .ok_or_else(|| refused("the vault records no owner to stamp the page invite grant"))
}

/// Mints the page's invite grant inside the owner's publication write (FIX
/// 7849): publishing a page is the owner act that lets its confirmed
/// bookings carry invites, and `setting` names that publication. The grant id
/// is derived from the page, so a republish finds the grant already stored
/// and writes nothing, and a grant the owner revoked stays revoked.
///
/// # Errors
///
/// Storage errors, and the grant's own validation.
pub(crate) fn mint_page_invite_grant_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    page_ref: EntityId,
    publisher_principal: EntityId,
    setting: &DerivedGrantSetting,
) -> crate::Result<()> {
    let id = page_invite_grant_id(&page_ref)
        .map_err(|_| Error::CorruptedIndex("booking page invite grant id"))?;
    if standing_outbound_grant_in_txn(&vault.store, txn, &id)?.is_some() {
        return Ok(());
    }
    mint_derived_page_invite_grant_in_txn(vault, txn, id, page_ref, publisher_principal, setting)?;
    Ok(())
}

/// The page's invite grant under `id`, minted through the derived consent
/// door for the publisher. `None`: the vault records no owner to stamp it.
fn mint_derived_page_invite_grant_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    page_ref: EntityId,
    publisher_principal: EntityId,
    setting: &DerivedGrantSetting,
) -> crate::Result<Option<StandingOutboundGrant>> {
    vault.mint_derived_outbound_grant_in_txn(
        txn,
        DerivedGrantOrigin::BookingInvite,
        setting,
        id,
        &publisher_principal.to_hex(),
        StandingOutboundGrantScope::BookingPageInvites { page_ref },
    )
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
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let wanted = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: *page_ref,
    };
    // The principal's grants come in id order, so the first live match is
    // the deterministic one.
    Ok(
        standing_outbound_grants_for_principal_in_txn(&vault.store, &rtxn, principal_ref)
            .map_err(|error| engine_failure("standing grant read", error))?
            .into_iter()
            .find(|grant| grant.is_active() && grant.scope == wanted)
            .map(|grant| (grant.id, grant)),
    )
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
