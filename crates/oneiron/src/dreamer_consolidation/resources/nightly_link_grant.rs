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

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_consolidation::resources::nightly_link_grant::NightlyLinkGrantRequest;

/// Mint the same bound the nightly landing door checks, with the normal
/// standing-grant receipt and revocation lifecycle. Nothing is minted by default.
/// It widens the Dreamer's grant: the owner's own mint goes on their own
/// proof, never gated, and the receipt records that decision (`check_in`).
/// With `check_in_ref` the owner applies another asker's approved check-in
/// for this grant, spent in the mint's writer (ROLES-CHECKIN 2k8; Engine
/// RULING P25-SHAPE Q1 = A, P25-2K8-SCOPE Q1 = A).
pub fn mint_nightly_link_grant(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: NightlyLinkGrantRequest,
) -> oneiron_contracts::memory::MemoryResult<crate::consent::lifecycle::ConsentActReceipt> {
    let applied = crate::verbs::check_in_ref(input.check_in_ref.as_deref())?.map(|id| {
        crate::check_in::AppliedCheckIn {
            id,
            verb: "vault.consent.create_nightly_link_grant",
            effect_digest: nightly_link_grant_effect_digest(),
        }
    });
    Ok(vault.with_write_txn_grouped(|txn| {
        let actor = vault.dreamer_authority_in_txn(txn, vault.now_recorded_at())?;
        crate::consent::lifecycle::create_standing_grant_with_decision_in_txn(
            vault,
            txn,
            owner,
            nightly_link_bound(actor)?,
            applied.as_ref(),
        )
    })?)
}

/// The digest of the owner's nightly-link grant: the effect an asker's
/// `vault.check_in.open` names for `vault.consent.create_nightly_link_grant`,
/// and the one the owner's mint spends (2k8). The request names nothing: the
/// vault resolves its own Dreamer, so the effect is one constant, BLAKE3
/// with its key derived from `oneiron check_in nightly link grant v1` over
/// no input.
#[must_use]
pub fn nightly_link_grant_effect_digest() -> [u8; 32] {
    *blake3::Hasher::new_derive_key("oneiron check_in nightly link grant v1")
        .finalize()
        .as_bytes()
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
