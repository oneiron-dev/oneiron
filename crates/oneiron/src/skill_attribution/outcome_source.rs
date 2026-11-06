//! FIX 3611: anchored pack outcomes read from stored sources. A host's
//! attribution source reads here whether a terminal success is anchored; no
//! model decides it. The one source now is a completed random audit of the
//! attempt's exact result: the seal's frozen contract, the capsule whose
//! bound answer is that result, and the loaded skill revisions the pack
//! pinned, read in one snapshot ([`stored_anchored_outcome`]). The outcome
//! comes with a witness of those rows, and the credit writer reads them
//! again in its own transaction ([`require_witness_in_txn`]). A source that
//! was erased, changed or never recorded answers unknown. A held-out
//! outcome has no producer of per-output correctness yet, and stays
//! unknown.

use crate::attempt_queue::ManifestKind;
use crate::learning::Anchor;
use crate::learning::honesty::SEAL_QUALITY_AXIS;
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_in_txn};
use crate::self_heal::audit::{SealedAudit, bound_random_audit_in_txn, pack_receipt_attempt};
use crate::{Error, Result, Vault};

use super::AnchoredPackOutcome;

/// An anchored pack outcome and the witness of the stored source it was
/// read from (FIX 3611).
#[derive(Debug, Clone, PartialEq)]
pub struct WitnessedPackOutcome {
    pub outcome: AnchoredPackOutcome,
    pub witness: OutcomeWitness,
}

/// The stored rows an anchored outcome was read from (FIX 3611): a
/// completed random audit of the attempt's exact result, with the capsule
/// whose bound answer it is, and the pack's pinned loaded revisions as they
/// resolved. Only this module builds one.
#[derive(Debug, Clone, PartialEq)]
pub struct OutcomeWitness {
    audit: SealedAudit,
    loaded: Vec<String>,
}

/// The anchored outcome of `receipt`'s attempt from a stored source, read
/// in one snapshot, with its witness; `None` while it has none. A completed
/// random audit of the attempt's exact result is an `Audit` outcome at the
/// audit's drawn rate on the seal's quality axis, a success when no finding
/// names a flaw, at its check time. It names no goal revision: it is the
/// unscoped audit-quality axis, not a project goal's judgment.
///
/// # Errors
///
/// Storage errors.
pub fn stored_anchored_outcome(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<Option<WitnessedPackOutcome>> {
    let txn = vault.store.env.read_txn()?;
    read_in_txn(vault, &txn, &receipt.receipt_id)
}

/// The credit writer's recheck, in its transaction `txn`: `outcome` and
/// `witness` are still what the stored source of `attempt_receipt`'s
/// outcome reads. An outcome with no witness (an owner's verdict) has no
/// stored source to read.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the source was erased or changed since
/// it was read, and storage errors.
pub(super) fn require_witness_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
    outcome: &AnchoredPackOutcome,
    witness: Option<&OutcomeWitness>,
) -> Result<()> {
    let Some(witness) = witness else {
        return Ok(());
    };
    let holds = read_in_txn(vault, txn, attempt_receipt)?
        .is_some_and(|fresh| fresh.outcome == *outcome && fresh.witness == *witness);
    if !holds {
        return Err(Error::InvalidClaimBody(
            "the anchored outcome's source changed before its credit was written",
        ));
    }
    Ok(())
}

/// [`stored_anchored_outcome`] for the terminal pack receipt
/// `attempt_receipt`, in `txn`.
fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
) -> Result<Option<WitnessedPackOutcome>> {
    let Some(receipt) = attempt_pack_receipt_in_txn(&vault.store, txn, attempt_receipt)? else {
        return Ok(None);
    };
    // A random audit draws only an attempt that completed.
    if receipt.outcome != "completed" {
        return Ok(None);
    }
    let Some(attempt) = pack_receipt_attempt(attempt_receipt) else {
        return Ok(None);
    };
    let Some(audit) = bound_random_audit_in_txn(vault, txn, attempt)? else {
        return Ok(None);
    };
    let loaded = pinned_loaded_revisions_in_txn(vault, txn, &receipt)?;
    let contract = &audit.contract;
    let outcome = AnchoredPackOutcome {
        receipt: contract.check.clone(),
        anchor: Anchor::Audit {
            rate: contract.rate,
        },
        succeeded: contract.passed(),
        axis: SEAL_QUALITY_AXIS.to_owned(),
        at: contract.checked_at,
        goal_revision: None,
    };
    Ok(Some(WitnessedPackOutcome {
        outcome,
        witness: OutcomeWitness { audit, loaded },
    }))
}

/// Each skill the pack pinned a loaded revision of, as that revision
/// resolves in `txn` (`skill_id@version`), in the pack's order. A pinned
/// skill that no longer resolves is left out.
fn pinned_loaded_revisions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &ReceiptRecord,
) -> Result<Vec<String>> {
    let mut loaded = Vec::new();
    for entry in receipt.pack_manifest_entries().unwrap_or_default() {
        if entry.kind != ManifestKind::Skill {
            continue;
        }
        let Some((skill, _)) = entry.revision else {
            continue;
        };
        if let Some(record) =
            crate::skill::receipt_skill_record_in_txn(vault, txn, receipt, &skill)?
        {
            loaded.push(format!("{}@{}", record.skill_id, record.version));
        }
    }
    Ok(loaded)
}
