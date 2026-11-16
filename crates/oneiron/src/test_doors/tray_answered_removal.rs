//! Doors for `tests/tray_answered_removal.rs` (FIX 22394 CONSENT-TRAY): a
//! tray removal says `Answered` only with the proof the owner's answer closed
//! the claim's obligation, and that answer settles the claim's hold.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GateDecisionId, PENDING_GATE_CONSENT_VERSION, PendingGateConsentRecord};

/// The diff handle of the critical confirm the doors attach.
const CONFIRM_DIFF_HANDLE: &[u8] = b"tray-answered-removal";

/// The hold before and after one tray removal: whether `claim` read settled
/// with its critical row in the tray, and whether it reads settled after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettledAround {
    /// Settled with the critical row in the tray, before the removal.
    pub before: bool,
    /// Settled after the removal.
    pub after: bool,
}

/// Attaches a critical confirm to `claim`, as a critical Auto write leaves
/// it. The tray's put opens the claim's owner-answer obligation.
fn attach_critical_confirm(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
    seed: u8,
) -> Result<()> {
    let row = PendingGateConsentRecord {
        version: PENDING_GATE_CONSENT_VERSION,
        claim_id: *claim.as_bytes(),
        decision_id: GateDecisionId::from_bytes([seed; 16]),
        created_at: 1_000,
        diff_handle: CONFIRM_DIFF_HANDLE.to_vec(),
        read_frontier_hash: [seed; 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
        predicate: None,
        expires_at: None,
    };
    vault.store.put_pending_gate_consent_in_txn(wtxn, &row)
}

fn settled(vault: &Vault, wtxn: &heed::RwTxn<'_>, claim: &EntityId) -> Result<bool> {
    crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, wtxn, claim)
}

/// A critical confirm the vault's owner answers in person: the door
/// revalidates the embedded owner's proof in the answering transaction,
/// closes the claim's obligation with that answer to the confirm's item, and
/// removes the row as the close says. `None` when the proof answers nothing.
///
/// # Errors
/// The vault's and the store's.
pub fn remove_confirm_with_the_owners_answer(
    vault: &Vault,
    claim: &EntityId,
) -> Result<Option<SettledAround>> {
    let owner = vault.ensure_embedded_owner_actor().map_err(|error| {
        crate::error::Error::InvalidConfig(format!("embedded owner: {error:?}"))
    })?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.with_write_txn(|wtxn| {
        attach_critical_confirm(vault, wtxn, claim, 0x53)?;
        let before = settled(vault, wtxn, claim)?;
        let Some(answer) = proof.owner_answer_in_txn(vault, wtxn)? else {
            return Ok(None);
        };
        let removal = crate::gate::close_owner_answer_obligation_in_txn(
            &vault.store,
            wtxn,
            claim,
            CONFIRM_DIFF_HANDLE,
            crate::gate::OwnerAnswer::owner(&answer),
        )?;
        vault
            .store
            .remove_pending_gate_consent_in_txn(wtxn, claim, removal)?;
        let after = settled(vault, wtxn, claim)?;
        Ok(Some(SettledAround { before, after }))
    })
}
