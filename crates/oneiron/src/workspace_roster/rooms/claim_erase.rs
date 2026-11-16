//! An erased actor's name, out of the room claims that record it (FIX 3520;
//! HOMERETRY-CLAIM-AUTHOR = B, Engine 16 Nov 23:32): a claim's holder, and
//! the person a Retry's claim names as its author, read as the erased
//! identity once that actor is erased, in this vault's rows and in a carried
//! copy (FIX 4870).
use super::retry_claim::RETRY_CLAIM_RECEIPT_PREFIX;
use super::*;
use crate::receipt::ERASED_CALL_IDENTITY;

/// The person a Retry's claim receipt names as its author. `None` for any
/// other receipt, and for an author already erased.
pub(super) fn retry_claim_author(receipt_ref: &str) -> Option<EntityId> {
    EntityId::from_hex(receipt_ref.strip_prefix(RETRY_CLAIM_RECEIPT_PREFIX)?).ok()
}

/// Rewrites `claim` so that it names `actor` nowhere: as its holder, or as
/// the author of a Retry's claim, it names the erased identity instead.
/// Whether anything changed.
pub(super) fn erase_claim_actor(claim: &mut RoomClaimReceipt, actor: &EntityId) -> bool {
    let mut changed = false;
    if claim.actor == actor.to_hex() {
        claim.actor = ERASED_CALL_IDENTITY.to_owned();
        changed = true;
    }
    if retry_claim_author(&claim.receipt_ref) == Some(*actor) {
        claim.receipt_ref = format!("{RETRY_CLAIM_RECEIPT_PREFIX}{ERASED_CALL_IDENTITY}");
        changed = true;
    }
    changed
}

/// The receipt reference two copies of one claim carry, merged as a carried
/// holder is (REVIEW-4366 round 4): the same reference, or a Retry's claim
/// whose author one copy names and the other names as the erased identity,
/// which wins. `None` when they are not one receipt.
pub(super) fn merged_receipt_ref(held: &str, carried: &str) -> Option<String> {
    if held == carried {
        return Some(held.to_owned());
    }
    let author = crate::deletion::carrier_actor_merged(
        held.strip_prefix(RETRY_CLAIM_RECEIPT_PREFIX)?,
        carried.strip_prefix(RETRY_CLAIM_RECEIPT_PREFIX)?,
        ERASED_CALL_IDENTITY,
    )?;
    Some(format!("{RETRY_CLAIM_RECEIPT_PREFIX}{author}"))
}

/// The actor scrub `ROOMS_CLAIM` declares: every claim that names `actor`,
/// as its holder or as a Retry's author, names the erased identity instead.
/// A turn an erased holder claimed stays claimed, as a carried one does.
pub(crate) fn erase_claim_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for row in CLAIMS.iter_from(&vault.store, wtxn, &[])? {
        let (turn, mut claim) = row?;
        if erase_claim_actor(&mut claim, actor) {
            erased.push((turn, claim));
        }
    }
    for (turn, claim) in &erased {
        CLAIMS.put(&vault.store, wtxn, turn, claim)?;
    }
    Ok(())
}

/// Doors for `tests/room_home_retry_claim.rs` (HOMERETRY-CLAIM-AUTHOR = B):
/// a claim row planted and read raw, and a copy another machine of this
/// vault carried, merged as replica sync merges it. Compiled only under the
/// test-support cfg.
#[cfg(oneiron_test_support)]
pub(crate) mod doors {
    use super::super::replica::{RoomSideRow, SideMerge, merge_replicated_side_row_in_txn};
    use super::*;

    /// Writes `claim` as its turn's claim row.
    pub(crate) fn put_claim(vault: &Vault, claim: &RoomClaimReceipt) -> Result<()> {
        let turn = EntityId::from_hex(&claim.turn_id)?;
        vault.with_write_txn_grouped(|txn| CLAIMS.put(&vault.store, txn, &turn, claim))
    }

    /// `turn`'s claim row, raw.
    pub(crate) fn claim(vault: &Vault, turn: EntityId) -> Result<Option<RoomClaimReceipt>> {
        let txn = vault.store.env.read_txn()?;
        CLAIMS.get(&vault.store, &txn, &turn)
    }

    /// Merges `claim` as a carried copy; the merge's outcome by name:
    /// `written`, `held`, `conflict` or `refused`.
    pub(crate) fn merge_carried_claim(
        vault: &Vault,
        claim: &RoomClaimReceipt,
    ) -> Result<&'static str> {
        let row = RoomSideRow::Claim {
            claim: claim.clone(),
        };
        let merged = vault
            .with_write_txn_grouped(|txn| merge_replicated_side_row_in_txn(vault, txn, &row))?;
        Ok(match merged {
            SideMerge::Written => "written",
            SideMerge::Held => "held",
            SideMerge::Conflict => "conflict",
            SideMerge::Refused(_) => "refused",
        })
    }
}
