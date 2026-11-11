//! Original Gate-selected pinned proofs live on the intent row whose spend
//! admitted them. Every retry reads that one canonical source and still
//! proves its current family, intent and digest. Co-actor keepers retain
//! their separate post-commit failure policy below.

use super::types::{AdmittedApproval, IntentId};
use crate::Vault;
use crate::gate::ExternalEffectGateInput;

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

pub(crate) use crate::consent::approval_proof::{PinnedApproval, PinnedApprovalFamily};

/// The original spent press on this exact intent, only while the current
/// effect still pins its family and digest. An absent, erased or unreadable
/// record leaves the retry on its existing path; no marker mints a proof.
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
    let record = super::store::read_stored_intent_record_in_txn(vault, txn, &intent_id)
        .ok()
        .flatten()?;
    if super::payload::payload_erased(record.payload()).ok()? {
        return None;
    }
    let approval = record.pinned_approval?;
    (approval.family == family
        && approval.proof.intent_id() == intent_id
        && crate::gate::external_effect_approval_digest(effect)
            == Some(approval.proof.effect_digest()))
    .then_some(approval.proof)
}
