//! Door for `tests/owner_key_vouch.rs` (REVIEW2 #8796 P3-1 b): the vouch
//! door's check that the machine a request names holds it as the owner's
//! machine, on this vault's read-only fold rewritten so that the machine also
//! has an anchor's chain. No public door makes an anchor-admitted chain of a
//! machine the roster removed, so the fold is shaped here, as
//! `archive_provenance` shapes one.

use crate::Vault;
use crate::authority::{OwnerKeyVouchRequest, require_holding_machine};
use crate::error::{Error, Result};

/// The vouch door's holding-machine check of `request`
/// (`require_holding_machine`) on this vault's read-only fold, in which the
/// machine `request` names also has a chain under `anchor_key`: a copy of its
/// roster chain, so live, signed by the same install key and of the same
/// role. With `remove_roster_chain` the roster chain is marked removed, as a
/// roster removal leaves it, and the anchor's chain stays live.
///
/// # Errors
/// The check's refusal; the fold's; the machine has no roster chain on this
/// vault's fold.
pub fn require_holding_machine_beside_anchor_chain(
    vault: &Vault,
    request: &OwnerKeyVouchRequest,
    anchor_key: [u8; 32],
    remove_roster_chain: bool,
) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    let mut fold = vault.authority_fold_readonly_in_txn(&rtxn)?;
    let folded = fold
        .machines
        .get_mut(&request.machine)
        .ok_or(Error::InvariantViolation(
            "the machine has no folded revision",
        ))?;
    let roster = folded
        .roster
        .as_mut()
        .ok_or(Error::InvariantViolation("the machine has no roster chain"))?;
    let anchored = roster.clone();
    if remove_roster_chain {
        roster.removed = true;
    }
    folded.anchored.insert(anchor_key, anchored);
    require_holding_machine(&fold, request)
}
