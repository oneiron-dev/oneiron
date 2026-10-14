//! Each engine sweep, called through its own door, within its own bound.
//!
//! Bounds: the critical-confirm sweep walks 256 pending rows a page and the
//! gate-decision sweep removes at most the manifest's rows a pass, both
//! stopping between pages at the pass deadline. The signing sweeps and the
//! cache eviction walk their tables a page at a time from a durable cursor and
//! stop between pages at the deadline; a signing page that fails is retried a
//! document at a time, so one document that fails cannot hold the others. The
//! rest scan their own table in one call: the lease and print sweeps when a
//! deadline a door noted comes due and hourly besides, symbol holds every five
//! minutes, and the erasure sweep daily, hourly while an obligation waits. The
//! lease sweep also retries a bounded number of files a revoke or an expiry
//! could not remove then.

use super::{Deadline, HardEraseWork, HousekeepingSweep, SweepWork};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The cache's hard age bound: the longest serve window (ARCH-0019, Dormant
/// 168 h), so eviction never takes a row the read gate could still serve.
const PPR_CACHE_MAX_AGE_SECS: u64 = 168 * 60 * 60;

/// Kept secret-lease files one run tries to remove again.
const SECRET_TEARDOWN_RETRIES: usize = 64;

/// Rows one cache-eviction page reads.
const PPR_CACHE_PAGE: usize = 512;

/// Draft claims one signing page reads, well inside the signing doors' batch
/// bound of 100 documents.
const ESIGN_PAGE: usize = 32;

/// What one sweep run did.
pub(super) struct Run {
    pub(super) work: SweepWork,
    /// Whether the sweep finished its work. An unfinished sweep is due again
    /// on the next pass.
    pub(super) complete: bool,
    /// Where an unfinished paged walk goes on from.
    pub(super) cursor: Option<Vec<u8>>,
}

impl Run {
    fn complete(work: SweepWork) -> Self {
        Self {
            work,
            complete: true,
            cursor: None,
        }
    }
}

/// Runs one sweep from `cursor`, the point an unfinished walk of the same
/// sweep stopped at.
pub(super) fn run(
    vault: &Vault,
    sweep: HousekeepingSweep,
    now: u64,
    deadline: &Deadline,
    cursor: Option<&[u8]>,
) -> Result<Run> {
    let work = match sweep {
        HousekeepingSweep::SecretLeaseExpiry => {
            let expired = count(vault.expire_secret_leases(now)?);
            let (files_removed, files_kept) =
                vault.retry_kept_secret_teardowns(now, SECRET_TEARDOWN_RETRIES)?;
            SweepWork::SecretLeases {
                expired,
                files_removed,
                files_kept,
            }
        }
        HousekeepingSweep::CriticalConfirmExpiry => return critical_confirms(vault, deadline),
        HousekeepingSweep::SymbolLeaseExpiry => SweepWork::SymbolLeases {
            released: count(vault.expire_symbol_leases(now)?.len()),
        },
        HousekeepingSweep::VoicePrintRetention => SweepWork::VoicePrints {
            pruned: count(vault.prune_expired_voice_prints(now)?.len()),
        },
        HousekeepingSweep::EsignExpiry => {
            let (walk, cursor) = esign_walk(vault, deadline, cursor, |documents| {
                vault.sweep_esign_expiry(documents, now)
            })?;
            return Ok(walk.run(cursor, |documents, expired, failed| {
                SweepWork::EsignExpiry {
                    documents,
                    expired,
                    failed,
                }
            }));
        }
        HousekeepingSweep::EsignSealBackstop => {
            let (walk, cursor) = esign_walk(vault, deadline, cursor, |documents| {
                vault.sweep_esign_seals(documents, now)
            })?;
            return Ok(walk.run(cursor, |documents, enqueued, failed| {
                SweepWork::EsignSeals {
                    documents,
                    enqueued,
                    failed,
                }
            }));
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
        HousekeepingSweep::PprCacheEviction => return ppr_cache(vault, now, deadline, cursor),
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
    Ok(Run::complete(work))
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Pages through the pending critical confirms until a whole walk that began
/// after this run started has ended, or the deadline passes. The expiry cursor
/// is durable and shared with the confirm listing, so a run that finds a walk
/// already in progress finishes it and then walks again from the head: only a
/// walk that began after the run started has seen every confirm due by then.
fn critical_confirms(vault: &Vault, deadline: &Deadline) -> Result<Run> {
    let expiry_cursor = || -> Result<Option<u64>> {
        let txn = vault.store.env.read_txn()?;
        Ok(vault
            .store
            .critical_confirm_expiry_sweep_state_in_txn(&txn)?
            .0)
    };
    let mut walks_to_end = if expiry_cursor()?.is_none() { 1 } else { 2 };
    let mut demoted = 0;
    let mut pages = 0;
    loop {
        demoted += count(vault.expire_critical_write_confirms()?);
        pages += 1;
        if expiry_cursor()?.is_none() {
            walks_to_end -= 1;
        }
        let complete = walks_to_end == 0;
        if complete || deadline.passed() {
            return Ok(Run {
                work: SweepWork::CriticalConfirms { demoted, pages },
                complete,
                cursor: None,
            });
        }
    }
}

/// Finishes staged key retirements, then ages out decisions past the owner's
/// horizon a pass at a time until a pass removes nothing or the deadline
/// passes. A vault with no horizon prunes nothing.
fn gate_decisions(vault: &Vault, deadline: &Deadline) -> Result<Run> {
    vault.finish_gate_decision_retirements()?;
    let mut removed = 0;
    let mut complete = true;
    if vault.gate_decision_retention_secs()?.is_some() {
        loop {
            let pass = vault.sweep_gate_decision_retention()?;
            removed += pass;
            if pass == 0 {
                break;
            }
            if deadline.passed() {
                complete = false;
                break;
            }
        }
    }
    Ok(Run {
        work: SweepWork::GateDecisions { removed },
        complete,
        cursor: None,
    })
}

/// Evicts the graph-walk cache a page at a time, each page its own short
/// write, until the walk ends or the deadline passes.
fn ppr_cache(vault: &Vault, now: u64, deadline: &Deadline, cursor: Option<&[u8]>) -> Result<Run> {
    let mut evicted = 0;
    let mut deps_cleaned = 0;
    let mut cursor = cursor.map(<[u8]>::to_vec);
    loop {
        let page = crate::ppr::evict_ppr_cache_page(
            &vault.store,
            cursor.as_deref(),
            PPR_CACHE_PAGE,
            PPR_CACHE_MAX_AGE_SECS,
            now,
        )?;
        evicted += page.evicted;
        deps_cleaned += page.deps_cleaned;
        cursor = page.cursor;
        if cursor.is_none() || deadline.passed() {
            return Ok(Run {
                work: SweepWork::PprCache {
                    evicted,
                    deps_cleaned,
                },
                complete: cursor.is_none(),
                cursor,
            });
        }
    }
}

fn hard_erase(vault: &Vault) -> Result<HardEraseWork> {
    let windows_unloaded = if super::schedule::erase_obligation_waiting(vault)? {
        unload_idle_windows(vault)
    } else {
        0
    };
    let run = crate::sweep::run_hard_erase_sweep(vault)?;
    Ok(HardEraseWork {
        jobs_processed: run.jobs_processed,
        jobs_deferred: run.jobs_deferred,
        windows_unloaded,
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

/// A host keeps every window it served registered until it stops, and the
/// erasure sweep defers every registered window as live. Before it compacts,
/// each window that no caller holds is written down and closed through the
/// manager's own unload, which refuses a window someone holds; the next touch
/// opens it again from its rows. A refused or failed unload leaves the window
/// as it was, and the sweep defers it.
#[cfg(feature = "sync")]
fn unload_idle_windows(vault: &Vault) -> u64 {
    let manager = vault
        .live_window_manager
        .lock()
        .ok()
        .and_then(|manager| manager.upgrade());
    let Some(manager) = manager else {
        return 0;
    };
    let mut unloaded = 0;
    for key in manager.loaded_keys() {
        if matches!(manager.unload_window(&key), Ok(true)) {
            unloaded += 1;
        }
    }
    unloaded
}

#[cfg(not(feature = "sync"))]
fn unload_idle_windows(_vault: &Vault) -> u64 {
    0
}

/// What a signing walk counted.
#[derive(Default)]
struct EsignWalk {
    documents: u64,
    done: u64,
    failed: u64,
}

impl EsignWalk {
    fn run(self, cursor: Option<Vec<u8>>, work: impl FnOnce(u64, u64, u64) -> SweepWork) -> Run {
        Run {
            work: work(self.documents, self.done, self.failed),
            complete: cursor.is_none(),
            cursor,
        }
    }
}

/// Walks the signing documents a page at a time from `cursor`, calling
/// `sweep_page` on each page and, when a page fails, on each of its documents
/// alone. Stops between pages at the deadline and returns where it stopped,
/// or `None` once the walk ended.
fn esign_walk(
    vault: &Vault,
    deadline: &Deadline,
    cursor: Option<&[u8]>,
    sweep_page: impl Fn(&[EntityId]) -> Result<usize>,
) -> Result<(EsignWalk, Option<Vec<u8>>)> {
    // A cursor that does not decode starts the walk over.
    let mut after = cursor
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        .and_then(|raw| EntityId::from_bytes(raw).ok());
    let mut walk = EsignWalk::default();
    loop {
        let (documents, last) = {
            let txn = vault.store.env.read_txn()?;
            crate::blob_artifact::esign::esign_document_page_in_txn(vault, &txn, after, ESIGN_PAGE)?
        };
        walk.documents += count(documents.len());
        match sweep_page(&documents) {
            Ok(n) => walk.done += count(n),
            Err(_) => {
                for document in &documents {
                    match sweep_page(std::slice::from_ref(document)) {
                        Ok(n) => walk.done += count(n),
                        Err(_) => walk.failed += 1,
                    }
                }
            }
        }
        let Some(last) = last else {
            return Ok((walk, None));
        };
        if deadline.passed() {
            return Ok((walk, Some(last.as_bytes().to_vec())));
        }
        after = Some(last);
    }
}
