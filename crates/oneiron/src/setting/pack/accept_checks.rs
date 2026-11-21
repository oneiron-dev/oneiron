//! The checks an owner's yes to a pack's waiting proposal passes before anything is written.
//!
//! [`Vault::accept_pack_defaults`] makes them on a read before it asks for the person at this
//! device, so a yes they refuse raises no prompt, and its write makes them again.

use super::*;

/// An owner's yes that passed [`checked_accept_in_txn`].
pub(super) struct CheckedAccept {
    /// The owner, revalidated.
    pub(super) by: EntityId,
    /// The pack's head, its waiting proposal taken out.
    pub(super) head: PackHead,
    /// The proposal the yes names.
    pub(super) waiting: PackProposal,
    /// Each proposed default's key and the row it replaces, in the proposal's order.
    pub(super) checked: Vec<(&'static SettingSpec, Option<StoredRow>)>,
}

/// Checks the owner `owner`'s yes to `pack`'s waiting proposal `proposal` on a read of the
/// store: the owner's proof, the pack's head, the waiting proposal, and for each of its defaults
/// a key this build knows, a row that did not move since the proposal and a value its key
/// decodes. On a rooted vault the write appends the yes as an act, so the yes also needs what
/// that append refuses for with nothing of the person's answer in it: a head digest that decodes
/// ([`head_defaults_digest`]) and, for a head that names a version, an install that can carry
/// the owner's act ([`Vault::owner_act_carrier_stands_in_txn`]). A head from before versions
/// keeps its yes on this install, so it needs no carrier.
///
/// # Errors
///
/// An owner proof that no longer holds; `InvalidConfig` for a pack with no head, a proposal that
/// is not the pack's waiting one, a row that moved since, or a key this build does not know; on
/// a rooted vault, `CorruptedIndex` for a head whose digest is not 64 hex digits, and the
/// append's typed refusal for an install that cannot carry the owner's act; storage errors.
pub(super) fn checked_accept_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
    pack: &str,
    proposal: &str,
) -> Result<CheckedAccept> {
    let by = owner.revalidate_in_txn(vault, txn)?;
    let Some(mut head) = head_in_txn(&vault.store, txn, pack)? else {
        return Err(Error::InvalidConfig(format!(
            "no pack named `{pack}` has defaults in this vault"
        )));
    };
    let Some(waiting) = head
        .proposal
        .take()
        .filter(|waiting| waiting.digest == proposal)
    else {
        return Err(Error::InvalidConfig(format!(
            "pack `{pack}` has no waiting proposal `{proposal}`: read the list again"
        )));
    };
    let mut checked = Vec::with_capacity(waiting.defaults.len());
    for proposed in &waiting.defaults {
        let spec = spec_named(&proposed.key)?;
        let current =
            table_of(spec).get_bytes(&vault.store, txn, &pack_row_key(spec.name, pack))?;
        if current.as_deref().map(row_digest) != proposed.replaced
            || !spec.kind.decodes(&proposed.value)
        {
            return Err(Error::InvalidConfig(format!(
                "the default of `{}` moved since proposal `{proposal}`: the pack door proposes \
                 again at its next run",
                proposed.key
            )));
        }
        let prior = current
            .as_deref()
            .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok());
        checked.push((spec, prior));
    }
    // What the append of the yes's act refuses for before it signs, in the append's order.
    if rooted_in_txn(vault, txn)? {
        let _ = head_defaults_digest(&head);
        if !head.version.is_empty() {
            vault.owner_act_carrier_stands_in_txn(txn)?;
        }
    }
    Ok(CheckedAccept {
        by,
        head,
        waiting,
        checked,
    })
}

/// The digest of the defaults `head` names, decoded.
///
/// # Errors
///
/// `CorruptedIndex` for a head whose digest is not 64 hex digits.
pub(super) fn head_defaults_digest(head: &PackHead) -> Result<[u8; 32]> {
    oneiron_hex::decode::<32>(&head.digest).ok_or(Error::CorruptedIndex(
        "a pack head's digest is not 64 hex digits",
    ))
}
