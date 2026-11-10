//! The supersession item (kind 3): a claim an agent derived replaces one its
//! live `derive` grant reaches, through the claim lifecycle's own
//! supersession, never over user-stated truth, and only once the replacement
//! itself stands.

use super::batch::DerivedSupersede;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource};
use crate::error::{Error, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Vault};

/// The refusal of a supersession that would close user-stated truth: any
/// replacement over a user-stated (or unlabelled) claim, a stored
/// user-stated replacement included.
pub const SUPERSEDE_PROTECTED_SOURCE: &str = "gate.deny.derive.supersede_protected_source";

/// The refusal of a supersession whose replacement does not stand yet: a
/// proposal, a rejected claim, or a claim whose critical confirmation the
/// owner has not answered.
pub const SUPERSEDE_REPLACEMENT_UNSETTLED: &str =
    "gate.deny.derive.supersede_replacement_unsettled";

/// The refusal of a supersession the claim lifecycle does not allow: either
/// side is not a live claim, the old one is already closed, or a claim names
/// itself.
pub const SUPERSEDE_LIFECYCLE: &str = "gate.deny.derive.supersede_lifecycle";

/// The reason a landed supersession's receipt names.
const SUPERSEDE_ALLOWED: &str = "gate.allow.derive.supersede";

/// Stages `item`: the derive verdict over the old claim, the source-trust
/// guard, the replacement's standing, then the supersession in a savepoint
/// of `txn`.
///
/// # Errors
///
/// Storage errors, and any error the lifecycle raises other than its
/// refusal of this pair: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedSupersede,
) -> Result<ItemOutcome> {
    let new = context.resolve(&item.new)?;
    let old = context.resolve(&item.old)?;
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        context.stamp.actor,
        DeriveCapability::Derive,
        Some(old),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, old, refusal.token()),
    };
    let (Some(new_body), Some(old_body)) = (
        claim_body_in(vault, txn, new)?,
        claim_body_in(vault, txn, old)?,
    ) else {
        return refuse(vault, txn, context, old, SUPERSEDE_LIFECYCLE);
    };
    // A person alone closes user-stated (or unlabelled) truth, whatever
    // replaces it. The lifecycle's own guard asks only about a generated
    // replacement, so a stored user-stated claim named as `new` passes it.
    if matches!(old_body.source, None | Some(ClaimSource::UserStated))
        || Vault::require_source_trust_supersession_rights(&new_body, &old_body).is_err()
    {
        return refuse(vault, txn, context, old, SUPERSEDE_PROTECTED_SOURCE);
    }
    // A replacement that still waits closes nothing: until it is approved
    // and its critical confirmation answered it is not in recall, so the
    // claim it would close must stand.
    if !matches!(
        new_body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &new)?
    {
        return refuse(vault, txn, context, old, SUPERSEDE_REPLACEMENT_UNSETTLED);
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match vault.supersede_claim_in_txn_as(
        &mut savepoint,
        &new,
        &old,
        context.now,
        Some(context.stamp.actor),
    ) {
        Ok(()) => {
            savepoint.commit()?;
            let receipt = allowance_receipt_in_txn(
                vault,
                txn,
                context,
                Some(old),
                &[SUPERSEDE_ALLOWED.to_owned()],
                &allowance,
            )?;
            Ok(ItemOutcome::Landed {
                rows: vec![new, old],
                approval: None,
                receipt: Some(receipt),
            })
        }
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            savepoint.abort();
            refuse(vault, txn, context, old, SUPERSEDE_LIFECYCLE)
        }
        Err(error) => Err(error),
    }
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    old: EntityId,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, Some(old), &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}

/// The stored body of the claim `id` in `txn`; `None` for a row that is not
/// a claim, or is gone.
fn claim_body_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<ClaimBody>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store.read(), txn, &id)?
    else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    Ok(crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).ok())
}
