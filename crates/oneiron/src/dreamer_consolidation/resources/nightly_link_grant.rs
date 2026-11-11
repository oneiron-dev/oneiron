//! The owner's standing grant that lets the Dreamer apply the SameAs links
//! its nightly continuations propose (FIX 8363, L02 02:15). It is the
//! owner's own standing action grant (DEC-0006): its bound names the
//! Dreamer's System actor, the verb [`NIGHTLY_LINK_VERB`] and the selector
//! [`NIGHTLY_LINK_SELECTOR`], and an owner mints it through the standing
//! grant door like any other. Nothing mints one by default. Without a live
//! one each link stays a proposed status claim, as before.

use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::write_envelope::WriteActor;
use crate::{Result, Vault};

/// The verb an owner's grant names to let the Dreamer apply its nightly
/// SameAs links.
const NIGHTLY_LINK_VERB: &str = "dreamer.nightly_link.apply";
/// The one selector that grant's envelope holds: every nightly SameAs link
/// the Dreamer proposes, in this vault.
const NIGHTLY_LINK_SELECTOR: &str = "dreamer:nightly-links";

/// The bound an owner's grant must contain for `actor` to apply a link.
fn nightly_link_bound(actor: WriteActor) -> Result<GrantBound> {
    GrantBound::action(
        ActorBound::new(actor.entity_ref().to_hex())?
            .with_actor_class(actor.actor_class().gate_actor_class())?,
        ActionClass::new(NIGHTLY_LINK_VERB)?,
        ActionEnvelope::new([NIGHTLY_LINK_SELECTOR.to_owned()])?,
    )
}

/// The owner grants the vault's own Dreamer its existing nightly-link bound.
/// The writer is resolved by the vault, never supplied by the caller.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NightlyLinkGrantRequest {}

/// Mint the same bound the nightly landing door checks, with the normal
/// standing-grant receipt and revocation lifecycle. Nothing is minted by default.
pub fn mint_nightly_link_grant(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    _input: NightlyLinkGrantRequest,
) -> oneiron_contracts::memory::MemoryResult<crate::consent::lifecycle::ConsentActReceipt> {
    let receipt = vault.with_write_txn_grouped(|txn| {
        let actor = vault.dreamer_authority_in_txn(txn, vault.now_recorded_at())?;
        vault.create_standing_grant_in_txn(txn, owner, nightly_link_bound(actor)?)
    })?;
    Ok(receipt.into())
}

/// The ref of the owner's live standing grant letting `actor` apply its
/// nightly SameAs links, read in `txn`, the write that applies them: an
/// active grant whose bound contains [`nightly_link_bound`] and whose
/// minting owner is a live owner of the vault now. `None` when there is
/// none: the links stay proposed, with no refusal or hold.
pub(crate) fn require_nightly_link_write(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Result<Option<String>> {
    let required = nightly_link_bound(actor)?;
    for grant in vault.active_standing_consent_grants_in_txn(txn)? {
        if !grant.bound().contains(&required) {
            continue;
        }
        let grant_ref = grant.bound().digest().to_hex();
        let Some(row) = vault.consent_grant_in_txn(txn, &grant_ref)? else {
            continue;
        };
        if row.is_active()
            && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &row.owner_stamp.actor)?
        {
            return Ok(Some(grant_ref));
        }
    }
    Ok(None)
}
