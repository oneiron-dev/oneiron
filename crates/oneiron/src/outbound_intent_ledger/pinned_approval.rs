//! FIX 6424 part 2a (Engine 10-20 21:0x ruling 8, CALLS `FIX 6424 pinned
//! Pending proof retention`): the owner's one-send press a Linear dispatch's
//! or a campaign leg's first admission spent, kept beside its ledger row.
//! Part 3 (2b) files a scoped-MCP call's the same way: its row binds an
//! endpoint and a capability, which that row field's check refuses.
//!
//! The row's own `admitted_approval` field keeps native mail's, e-sign's and
//! a failure-signal batch's proof, validated by recomposing its digest from
//! the frozen payload for the row's server and tool. A campaign leg rides
//! any channel (email among them) on its program's raw body, so that check
//! cannot name it, and a Linear dispatch freezes no pinned send ref; this
//! table keeps their press apart, filed under the family its pinned target
//! names, and leaves that field, its codec and its validation untouched.
//!
//! The press is written once the admission that spent it and inserted the
//! Pending row has committed, in a writer of its own
//! ([`keep_press_after_admission`]): a press that does not write is logged
//! and the admission stands, so its send proceeds as before this table. A
//! retry of that row reads it under the same retry context; the Gate reuses
//! it only while the retry's own pinned digest is the kept one. A row that
//! does not read, or was never written, leaves the retry on its existing
//! path, as before this table.

use super::types::{AdmittedApproval, IntentId, IntentLedgerError};
use crate::Vault;
use crate::gate::ExternalEffectGateInput;
use crate::side_table::{self, Raw, SideTable};

/// The kept press's row layout version.
const PINNED_APPROVAL_VERSION: u8 = 1;

/// FIX 6424 part 2a (CALLS `FIX 6424 kept press write failure`): a spent
/// press that does not write never fails the admission that spent it. The
/// write is logged with the intent or operation it names and the admission
/// stands: its send proceeds as it did before part 2a, and a later retry,
/// finding no kept press, takes the existing retry path. `false` would
/// return the write's error to the caller instead.
pub(crate) const KEPT_PRESS_WRITE_FAILURE_CONTINUES: bool = true;

/// Writes one spent press with `write`, in a writer of its own, once the
/// admission that spent it has committed. A failure is logged with
/// `subject` (the intent or operation, hex) and, under
/// [`KEPT_PRESS_WRITE_FAILURE_CONTINUES`], leaves the admission as it stands.
///
/// # Errors
/// The write's own failure, only when that constant is `false`.
pub(crate) fn keep_press_after_admission<E>(
    vault: &Vault,
    subject: &str,
    write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<crate::error::Error> + std::fmt::Display,
{
    match vault.try_with_write_txn(write) {
        Err(error) if KEPT_PRESS_WRITE_FAILURE_CONTINUES => {
            tracing::warn!(
                reason = "approve_once_press_not_kept",
                subject,
                %error,
                "an owner's spent approve-once press was not kept for its retry; \
                 the admission stands and its retry asks as before"
            );
            Ok(())
        }
        kept => kept,
    }
}

/// Intent id → version, family tag, then the spent press's 32-byte digest.
const PINNED_APPROVAL: SideTable<IntentId, [u8; 34], Raw> =
    SideTable::new(&side_table::OUTBOUND_PINNED_APPROVAL);

pub(crate) use crate::consent::approval_proof::{PinnedApproval, PinnedApprovalFamily};

/// Keeps `approval` beside its Pending row, in a writer of its own once the
/// admission that spent it has committed ([`keep_press_after_admission`]).
/// `None` keeps nothing.
///
/// # Errors
/// A storage failure of that writer.
pub(crate) fn keep_pinned_approval_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    approval: Option<PinnedApproval>,
) -> Result<(), IntentLedgerError> {
    let Some(approval) = approval else {
        return Ok(());
    };
    // FIX 6835 P1: the admission committed before this writer opened, so an
    // erase of the request may have committed in between and already dropped
    // any press beside it; recheck the ledger row here and skip the put when
    // its request is erased or absent. A missing press only re-asks on retry.
    let intent_id = approval.proof.intent_id();
    let erased_or_absent = match super::store::get_ledger_record(vault, &*wtxn, &intent_id)? {
        Some(record) => super::payload::payload_erased(record.payload())?,
        None => true,
    };
    if erased_or_absent {
        return Ok(());
    }
    let mut value = [0_u8; 34];
    value[0] = PINNED_APPROVAL_VERSION;
    value[1] = approval.family.tag();
    value[2..].copy_from_slice(approval.proof.effect_digest().as_bytes());
    PINNED_APPROVAL.put(&vault.store, wtxn, &approval.proof.intent_id(), &value)?;
    Ok(())
}

/// FIX 6835: drops the press kept beside ledger row `intent_id`, in the
/// erase's own writer ([`super::store::put_erased_record`], the funnel both
/// erase paths share). A kept press authorizes nothing without its ledger
/// row, and a missing one only re-asks, so the delete is unconditional.
pub(crate) fn drop_pinned_approval_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    intent_id: &IntentId,
) -> crate::error::Result<()> {
    PINNED_APPROVAL.delete(&vault.store, wtxn, intent_id)?;
    Ok(())
}

/// The press `intent_id`'s first admission spent, kept for a retry whose
/// live `effect` pins the same family. `None` for none kept, another family,
/// or a row that does not read: that retry stays on its existing path.
pub(crate) fn pinned_retry_approval(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent_id: IntentId,
    effect: &ExternalEffectGateInput,
) -> Option<AdmittedApproval> {
    let family = effect
        .provenance
        .approval_target
        .as_ref()?
        .pinned_family()?;
    let value = PINNED_APPROVAL
        .get(&vault.store, txn, &intent_id)
        .ok()
        .flatten()?;
    if value[0] != PINNED_APPROVAL_VERSION || value[1] != family.tag() {
        return None;
    }
    let digest: [u8; 32] = value[2..].try_into().ok()?;
    Some(AdmittedApproval::from_gate(
        intent_id,
        crate::consent::EffectDigest::from_bytes(digest),
    ))
}
