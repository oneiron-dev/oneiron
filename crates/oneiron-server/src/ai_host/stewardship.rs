//! Follow-up drafts for due stewardship reach-outs (ARCH-0026 Represent).
//!
//! The engine names each pending reach-out whose owner rule routes drafts.
//! This host reads the reach-out's sources through the representation seam,
//! asks the drafting role once on the drafting budget (once more, over the
//! newest sources, when that call fails: `draft`), and hands the answer
//! back pre-materialized. The owner's own instruction is the system
//! message; the sources go as data, each model the call reaches sent only
//! the sources its own destination may receive (FIX 8714, `sources`), and
//! the draft scheduled with the evidence and voice the one that answered
//! was sent. What lands is a representation proposal
//! the owner reviews at `/v1/owner/representation` before any send. A draft
//! the owner's rule moved under while it was written is drafted again at
//! once against the current rule (FIX 6079), as is one whose sources moved
//! under a failure (FIX 7428). One that failed over unchanged inputs stays
//! pending and is tried again on its pace (`pace`, FIX 9465). The host's
//! pause (a managed reap freeze, FIX 6909) starts no next draft; what it
//! leaves stays pending.
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipDraftOutcome;
use oneiron::llm::manifest::ModelRole;
use tokio::sync::watch;

use self::draft::{DraftPass, draft_pass};
use self::pace::Pace;
use super::dreamer::{PassAdmission, admit, pause, paused};
use crate::config::models::DreamerSettings;
use crate::models::ModelRuntime;

mod draft;
mod pace;
mod sources;

/// The least time between two rounds: a burst of vault writes wakes one.
const SETTLE: Duration = Duration::from_secs(60);

/// What each follow-up draft is written on (FIX 1002): the owner's
/// `[models.dreamer.drafting]`, else the generative role and the Dreamer's
/// own pass budget, as drafts always were.
#[derive(Clone, Copy)]
pub(super) struct Drafter {
    /// The role its call is seated, admitted and routed on.
    pub(super) role: ModelRole,
    /// Each draft's line on the Dreamer's live budget policy rows.
    pub(super) budget_units: u64,
}

impl Drafter {
    /// The drafting `settings`, the Dreamer's resolved section, name.
    pub(super) fn of(settings: &DreamerSettings) -> Self {
        Self {
            role: settings.drafting.role(),
            budget_units: settings.drafting.budget_units(settings.pass_budget_units),
        }
    }
}

/// Drafts every due follow-up, then waits for the vault to change, for the
/// pause to lift, or for the next paced retry of a draft that failed (FIX
/// 9465). Runs on the Dreamer's thread and stops with it.
pub(super) async fn draft_loop(
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    drafter: Drafter,
    admission: PassAdmission,
) {
    let mut changes = vault.subscribe_proactivity_changes();
    let mut recoveries = runtime.recoveries();
    let mut pace = Pace::default();
    loop {
        // The pause epoch this round runs under, read before its gates, so a
        // freeze that races a gate reads as a pause.
        let epoch = pause(&admission);
        if let Err(error) = draft_round(
            &vault,
            &runtime,
            drafter,
            &admission,
            epoch.as_ref(),
            &mut pace,
        )
        .await
        {
            // By kind only: an engine error can quote the vault.
            tracing::warn!(kind = ?error.kind(), "stewardship drafts could not be listed");
        }
        tokio::time::sleep(SETTLE).await;
        // A round the pause held or refused also looks again once it lifts;
        // a paced retry wakes one when due, unless the pause holds.
        let due = if paused(epoch.as_ref()) {
            None
        } else {
            pace.next_due()
        };
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = pause_lifted(epoch) => {}
            () = retry_due(due) => {}
            recovered = recoveries.changed() => {
                if recovered.is_ok() {
                    pace.wake_all();
                }
            }
        }
    }
}

/// Resolves at `due`; pends with none.
async fn retry_due(due: Option<tokio::time::Instant>) {
    match due {
        Some(due) => tokio::time::sleep_until(due).await,
        None => std::future::pending::<()>().await,
    }
}

/// Resolves once the pause `epoch` held lifts: the epoch closed at a thaw,
/// or cleared. Pends while it holds none.
async fn pause_lifted(epoch: Option<watch::Receiver<bool>>) {
    match epoch {
        Some(mut epoch) if paused(Some(&epoch)) => {
            let _ = epoch.wait_for(|held| !*held).await;
        }
        _ => std::future::pending::<()>().await,
    }
}

/// Drafts every due follow-up: the reach-out index is read a page at a time,
/// each page a traversal unit, and its continuation followed to the end.
/// The host's gate is asked again before each page and each draft, and the
/// thread yields between drafts. A gate that refuses ends the round; the
/// rest stay pending, undrafted, for the next change. So does the host's
/// pause in `epoch` (FIX 6909), before each draft and each redraft. A
/// reach-out whose draft failed over the inputs it still has waits out its
/// `pace`; one whose inputs changed is drafted at once.
async fn draft_round(
    vault: &Vault,
    runtime: &ModelRuntime,
    drafter: Drafter,
    admission: &PassAdmission,
    epoch: Option<&watch::Receiver<bool>>,
    pace: &mut Pace,
) -> oneiron::Result<()> {
    let mut after = None;
    let mut seen = HashSet::new();
    loop {
        let page = {
            let Some(_pass) = admit(admission) else {
                return Ok(());
            };
            vault.stewardship_draft_page(after)?
        };
        for mut draft in page.drafts {
            seen.insert(draft.proposal);
            if !pace.due(&draft) {
                continue;
            }
            tokio::task::yield_now().await;
            let Some(_pass) = admit(admission) else {
                return Ok(());
            };
            // A draft the owner's rule moved under is drafted again at once
            // against the current rule (FIX 6079), and one whose sources
            // moved under a failure against the current request (FIX 7428):
            // a fresh request and a fresh call, each counted, with no cap. A
            // request read again that did not move is not drafted again in
            // this round.
            let mut redrafts: u64 = 0;
            loop {
                // The host's pause starts no next draft or redraft: this one
                // stays pending, not failed.
                if paused(epoch) {
                    return Ok(());
                }
                match draft_pass(vault, runtime, drafter, &draft).await? {
                    DraftPass::Done(StewardshipDraftOutcome::Scheduled(_)) | DraftPass::Gone => {
                        pace.clear(draft.proposal);
                        break;
                    }
                    DraftPass::Done(StewardshipDraftOutcome::Stale) => {
                        redrafts += 1;
                        tracing::info!(
                            proposal = %draft.proposal.to_hex(),
                            redrafts,
                            "a stewardship draft went stale against the owner's current rule"
                        );
                        let Some(current) = vault.stewardship_draft_request(draft.proposal)? else {
                            pace.clear(draft.proposal);
                            break;
                        };
                        if !current.moved_from(&draft) {
                            let wait = pace.failed(current);
                            tracing::warn!(
                                proposal = %draft.proposal.to_hex(),
                                retry_in_secs = wait.as_secs(),
                                "a stale stewardship draft's rule did not move; it stays pending"
                            );
                            break;
                        }
                        draft = current;
                    }
                    DraftPass::Moved(current) => {
                        redrafts += 1;
                        tracing::info!(
                            proposal = %draft.proposal.to_hex(),
                            redrafts,
                            "a stewardship draft's sources moved under its failure"
                        );
                        draft = current;
                    }
                    DraftPass::Failed(failure, input) => {
                        let wait = pace.failed(input);
                        // By kind only: an engine error can quote the vault.
                        tracing::warn!(
                            proposal = %draft.proposal.to_hex(),
                            stage = failure.stage.as_str(),
                            kind = ?failure.error.kind(),
                            retry_in_secs = wait.as_secs(),
                            "a stewardship follow-up was not drafted; it stays pending"
                        );
                        break;
                    }
                }
            }
        }
        let Some(next) = page.next else {
            // The whole index was read: the wait of a reach-out it no longer
            // names goes.
            pace.retain(&seen);
            return Ok(());
        };
        after = Some(next);
    }
}
