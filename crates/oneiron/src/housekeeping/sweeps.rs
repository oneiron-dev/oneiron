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
//! minutes, and the erasure sweep daily, hourly while an obligation waits; a
//! scheduled run rewrites windows only for a due obligation, since dropping
//! history is an erase, and the owner's run rewrites every window. The lease
//! sweep also retries a bounded number of files a revoke or an expiry could
//! not remove then.

use super::{Deadline, HardEraseWork, HousekeepingSweep, SweepWork};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, Vault};

/// What a lapse the host records carries as its provenance.
const COMMITMENT_LAPSE_PROVENANCE: &str = "oneiron.housekeeping.commitment_lapse.v1";

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
    /// The latest deadline a complete run has covered, when it is not the
    /// run's own start.
    pub(super) covered_until: Option<u64>,
}

impl Run {
    fn complete(work: SweepWork) -> Self {
        Self {
            work,
            complete: true,
            cursor: None,
            covered_until: None,
        }
    }
}

/// Runs one sweep from `cursor`, the point an unfinished walk of the same
/// sweep stopped at. `owner_asked` when the owner asked for this run rather
/// than its schedule making it due.
pub(super) fn run(
    vault: &Vault,
    sweep: HousekeepingSweep,
    now: u64,
    deadline: &Deadline,
    cursor: Option<&[u8]>,
    owner_asked: bool,
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
        HousekeepingSweep::CriticalConfirmExpiry => {
            return critical_confirms(vault, deadline, cursor);
        }
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
            let report = crate::commitment_lifecycle::lapse_overdue_commitments(
                vault,
                now,
                &lapse_envelope()?,
            )?;
            SweepWork::Commitments {
                lapsed: count(report.lapsed.len()),
                close_hooks_repaired: count(report.repaired_close_hooks.len()),
            }
        }
        HousekeepingSweep::GateDecisionRetention => return gate_decisions(vault, deadline),
        HousekeepingSweep::HardEraseSweep => SweepWork::HardErase(hard_erase(vault, owner_asked)?),
        HousekeepingSweep::PprCacheEviction => return ppr_cache(vault, now, deadline, cursor),
        HousekeepingSweep::SharedActMaturity => SweepWork::SharedActs {
            noticed: count(vault.notify_matured_shared_acts()?),
        },
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

/// Pages through the pending critical confirms until a walk this sweep saw
/// begin has ended, or the deadline passes. The expiry cursor is durable and
/// shared with the confirm listing, so a run that finds a walk already in
/// progress finishes it and then walks again from the head: only a walk whose
/// beginning is known has seen every confirm due by then, since each page
/// judges at the clock read in its own transaction. A walk that outlasts one
/// run goes on in the next, from the begin time `cursor` keeps. A complete
/// run covers the deadlines due by that time.
fn critical_confirms(vault: &Vault, deadline: &Deadline, cursor: Option<&[u8]>) -> Result<Run> {
    let mut began = cursor.and_then(confirm_walk_began);
    let mut demoted = 0;
    let mut pages = 0;
    loop {
        let page = vault.expire_critical_write_confirms_page()?;
        demoted += count(page.demoted);
        pages += 1;
        if let Some(at) = page.began_at {
            began = Some(at);
        }
        let complete = page.ended && began.is_some();
        if complete || deadline.passed() {
            return Ok(Run {
                work: SweepWork::CriticalConfirms { demoted, pages },
                complete,
                cursor: (!complete)
                    .then(|| began.map_or_else(Vec::new, |at| at.to_be_bytes().to_vec())),
                covered_until: began,
            });
        }
    }
}

/// When the walk an unfinished confirm run followed began, if it saw it
/// begin. One that does not decode starts over.
fn confirm_walk_began(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
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
        covered_until: None,
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
                covered_until: None,
            });
        }
    }
}

/// The envelope the host lapses an overdue instance under: the vault owner's,
/// as the owner-typed lifecycle doors act, observing that a due time passed.
/// The instance is the projector's signed birth, which only an ordinary
/// successor may replace; the projector's own envelope would have to rewrite
/// that birth.
fn lapse_envelope() -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(
            crate::vault::embedded_owner_actor_id()?,
            EdgeActorClass::Human,
        ),
        ClaimSource::Observed,
        WriteProvenance::new(rmpv::Value::from(COMMITMENT_LAPSE_PROVENANCE))?,
        ClaimApprovalStatus::Auto,
    ))
}

/// The erasure sweep. A scheduled run compacts history only for a due
/// obligation, and the owner's run compacts every window; either first
/// unloads the windows no caller holds, so the compaction can reach them.
fn hard_erase(vault: &Vault, owner_asked: bool) -> Result<HardEraseWork> {
    let windows_unloaded = if owner_asked || super::schedule::erase_obligation_waiting(vault)? {
        unload_idle_windows(vault)
    } else {
        0
    };
    let run = if owner_asked {
        crate::sweep::run_hard_erase_sweep(vault)?
    } else {
        crate::sweep::run_scheduled_hard_erase_sweep(vault)?
    };
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
            covered_until: None,
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
