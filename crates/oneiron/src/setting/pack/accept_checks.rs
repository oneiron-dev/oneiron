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
/// decodes.
///
/// # Errors
///
/// An owner proof that no longer holds; `InvalidConfig` for a pack with no head, a proposal that
/// is not the pack's waiting one, a row that moved since, or a key this build does not know;
/// storage errors.
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
    Ok(CheckedAccept {
        by,
        head,
        waiting,
        checked,
    })
}
