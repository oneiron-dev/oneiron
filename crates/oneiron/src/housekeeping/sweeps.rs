//! Each engine sweep, called through its own door, within its own bound.
//!
//! Bounds: the critical-confirm sweep walks 256 pending rows a page and the
//! gate-decision sweep removes at most the manifest's rows a pass, both
//! stopping between pages at the pass deadline. The signing sweeps take one
//! document at a time, so one document that fails cannot hold the others.
//! The rest scan their own table in one call: leases, prints and symbol holds
//! are small by construction; the erasure and cache sweeps are whole-vault
//! scans and run daily.

use super::{Deadline, HardEraseWork, HousekeepingSweep, SweepWork};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The cache's hard age bound: the longest serve window (ARCH-0019, Dormant
/// 168 h), so eviction never takes a row the read gate could still serve.
const PPR_CACHE_MAX_AGE_SECS: u64 = 168 * 60 * 60;

/// Runs one sweep. Returns its counts and whether it finished its work; an
/// unfinished sweep is due again on the next pass.
pub(super) fn run(
    vault: &Vault,
    sweep: HousekeepingSweep,
    now: u64,
    deadline: Deadline,
) -> Result<(SweepWork, bool)> {
    let work = match sweep {
        HousekeepingSweep::SecretLeaseExpiry => SweepWork::SecretLeases {
            expired: count(vault.expire_secret_leases(now)?),
        },
        HousekeepingSweep::CriticalConfirmExpiry => return critical_confirms(vault, deadline),
        HousekeepingSweep::SymbolLeaseExpiry => SweepWork::SymbolLeases {
            released: count(vault.expire_symbol_leases(now)?.len()),
        },
        HousekeepingSweep::VoicePrintRetention => SweepWork::VoicePrints {
            pruned: count(vault.prune_expired_voice_prints(now)?.len()),
        },
        HousekeepingSweep::EsignExpiry => {
            let (documents, expired, failed) =
                each_esign_document(vault, |document| vault.sweep_esign_expiry(&[document], now))?;
            SweepWork::EsignExpiry {
                documents,
                expired,
                failed,
            }
        }
        HousekeepingSweep::EsignSealBackstop => {
            let (documents, enqueued, failed) =
                each_esign_document(vault, |document| vault.sweep_esign_seals(&[document], now))?;
            SweepWork::EsignSeals {
                documents,
                enqueued,
                failed,
            }
        }
        HousekeepingSweep::CommitmentLapse => {
            // The projector's pinned MACHINE envelope: a lapse records that a
            // due time passed, as the projector records an occurrence.
            let envelope = crate::commitment_schedule::commitment_projection_envelope()?;
            let report =
                crate::commitment_lifecycle::lapse_overdue_commitments(vault, now, &envelope)?;
            SweepWork::Commitments {
                lapsed: count(report.lapsed.len()),
                close_hooks_repaired: count(report.repaired_close_hooks.len()),
            }
        }
        HousekeepingSweep::GateDecisionRetention => return gate_decisions(vault, deadline),
        HousekeepingSweep::HardEraseSweep => SweepWork::HardErase(hard_erase(vault)?),
        HousekeepingSweep::PprCacheEviction => {
            let mut txn = vault.store.env.write_txn()?;
            let (evicted, deps_cleaned) =
                crate::ppr::cleanup_ppr_cache(&vault.store, &mut txn, PPR_CACHE_MAX_AGE_SECS, now)?;
            txn.commit()?;
            SweepWork::PprCache {
                evicted,
                deps_cleaned,
            }
        }
        HousekeepingSweep::EsignReminders
        | HousekeepingSweep::ConsultSettlement
        | HousekeepingSweep::PolicyHoldPrune
        | HousekeepingSweep::TaskAttribution
        | HousekeepingSweep::AttemptLeaseReclaim
        | HousekeepingSweep::SelfHealDetectorRuns => {
            return Err(Error::InvariantViolation(
                "a host-only sweep reached the engine housekeeping pass",
            ));
        }
    };
    Ok((work, true))
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Pages through the pending critical confirms until the expiry cursor wraps
/// or the deadline passes. The cursor is durable, so an unfinished walk goes
/// on from where it stopped.
fn critical_confirms(vault: &Vault, deadline: Deadline) -> Result<(SweepWork, bool)> {
    let mut demoted = 0;
    let mut pages = 0;
    loop {
        demoted += count(vault.expire_critical_write_confirms()?);
        pages += 1;
        let txn = vault.store.env.read_txn()?;
        let (cursor, _) = vault
            .store
            .critical_confirm_expiry_sweep_state_in_txn(&txn)?;
        let complete = cursor.is_none();
        if complete || deadline.passed() {
            return Ok((SweepWork::CriticalConfirms { demoted, pages }, complete));
        }
    }
}

/// Finishes staged key retirements, then ages out decisions past the owner's
/// horizon a pass at a time until a pass removes nothing or the deadline
/// passes. A vault with no horizon prunes nothing.
fn gate_decisions(vault: &Vault, deadline: Deadline) -> Result<(SweepWork, bool)> {
    vault.finish_gate_decision_retirements()?;
    let mut removed = 0;
    if vault.gate_decision_retention_secs()?.is_some() {
        loop {
            let pass = vault.sweep_gate_decision_retention()?;
            removed += pass;
            if pass == 0 {
                break;
            }
            if deadline.passed() {
                return Ok((SweepWork::GateDecisions { removed }, false));
            }
        }
    }
    Ok((SweepWork::GateDecisions { removed }, true))
}

fn hard_erase(vault: &Vault) -> Result<HardEraseWork> {
    let run = crate::sweep::run_hard_erase_sweep(vault)?;
    Ok(HardEraseWork {
        jobs_processed: run.jobs_processed,
        jobs_deferred: run.jobs_deferred,
        jobs_failed: run.jobs_failed,
        windows_compacted: run.windows_compacted,
        windows_deferred_live: run.windows_deferred_live,
        windows_deferred_raced: run.windows_deferred_raced,
        receipts_finalized: run.receipts_finalized,
        deadline_breaches: run.deadline_breaches,
        quarantine_rows_expired: run.quarantine_rows_expired,
        obligations_missing: run.obligations_missing,
        obligations_undecodable: run.obligations_undecodable,
    })
}

/// Runs `sweep_one` over every signing document, one at a time. Returns the
/// documents seen, the sum of what each call counted, and the documents whose
/// call failed.
fn each_esign_document(
    vault: &Vault,
    sweep_one: impl Fn(EntityId) -> Result<usize>,
) -> Result<(u64, u64, u64)> {
    let documents = {
        let txn = vault.store.env.read_txn()?;
        crate::blob_artifact::esign::esign_documents_in_txn(vault, &txn)?
    };
    let mut done = 0;
    let mut failed = 0;
    for &document in &documents {
        match sweep_one(document) {
            Ok(n) => done += count(n),
            Err(_) => failed += 1,
        }
    }
    Ok((count(documents.len()), done, failed))
}
