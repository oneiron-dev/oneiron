//! One automatic whole-ref run of one mirror, and the passes over every
//! mirror (FIX 6866 part 2).
//!
//! A run takes the mirror's own push hold, never the repository's
//! coordinator: inbound pushes, landings and cutovers never wait on an
//! outbound child, and the child inherits the hold, so one that outlives a
//! crashed host keeps the mirror held until it exits. An interval or event
//! run finds the hold taken and leaves the mirror for the next pass; a
//! push-now waits for it. Under the hold the mirror's open plan settles
//! first (`publish::mirror_plan_run`), and a run that continued one reports
//! that plan alone: the next plan is frozen at a later cadence or event
//! (`full_auto`: the next wake or tick). Only a mirror with no open plan
//! reads its published refs and deletions, there, under the hold, and
//! freezes a new one. A `schedule` run plans exactly the selection the
//! scheduled mirror always pushed. A `full_auto` run plans its green selection
//! (`mirror_auto`) only when it differs from the plan it settled last, or a
//! push-now asks. An `ask_me` mirror only settles a plan left open when it
//! was switched: its unsent batches are paused, never sent. A run that
//! fails before egress is held: nothing goes out, the mirror row shows
//! `review_unavailable`, and the next run reviews again from scratch.

use std::path::PathBuf;

use super::mirror::{OriginMirrorPushes, OriginMirrorTarget, TARGETS};
use super::mirror_auto::ORIGIN_MIRROR_FULL_AUTO_MIN_DELAY_SECS;
use super::mirror_strategy::OriginMirrorSyncStrategy;
use super::publish::{MirrorRunScope, MirrorSelection};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitRefName, GitWire, GitWireRepo, lock_repository, try_lock_repository,
};

/// The directory, inside the repository's object store, whose lock is one
/// mirror's push hold: never the repository's own coordinator.
const ORIGIN_MIRROR_HOLD_DIR: &str = "oneiron-mirror-push";

/// What started a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MirrorTrigger {
    /// The lifecycle tick: a due `schedule` mirror, any `full_auto` one, or
    /// an open plan.
    Interval,
    /// A published-ref move or a green landing woke the pass.
    Event,
    /// The owner's push-now, with the owner it names when one is known.
    PushNow(Option<EntityId>),
}

impl MirrorTrigger {
    /// Whether a run with nothing to plan still records a run: the
    /// scheduled mirror and every push-now always did.
    pub(super) fn records_idle(self, strategy: OriginMirrorSyncStrategy) -> bool {
        matches!(self, Self::PushNow(_)) || strategy == OriginMirrorSyncStrategy::Schedule
    }
}

/// What one pass looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MirrorPass {
    /// Every due `schedule` mirror, every `full_auto` one, every open plan.
    Tick,
    /// Every `full_auto` mirror and every open plan; no cadence.
    Wake,
}

/// A whole-ref run that landed: its counts, the names the mirror now holds
/// from this vault, and the refs the census reads.
pub(super) struct WholeRefsRun {
    pub(super) refs: u64,
    pub(super) deleted: u64,
    pub(super) names: Vec<String>,
    pub(super) census: Vec<(GitRefName, GitOid)>,
}

impl Vault {
    /// One pass over every mirror target (module docs). `admit` takes the
    /// host's hold for one run, or `None` when it has none to give; `stop`
    /// asks the pass to start no further run.
    pub(super) fn push_origin_mirrors(
        &self,
        pass: MirrorPass,
        mut admit: impl FnMut() -> Option<Box<dyn Send>>,
        stop: impl Fn() -> bool,
    ) -> Result<OriginMirrorPushes> {
        let targets = {
            let txn = self.store.env.read_txn()?;
            TARGETS.scan(&self.store, &txn)?
        };
        let mut report = OriginMirrorPushes {
            targets: u64::try_from(targets.len()).unwrap_or(u64::MAX),
            ..OriginMirrorPushes::default()
        };
        let now = self.now_recorded_at();
        for (repo_id, target) in targets {
            let due = match target.sync_strategy {
                OriginMirrorSyncStrategy::Schedule => {
                    pass == MirrorPass::Tick
                        && target
                            .last
                            .as_ref()
                            .is_none_or(|run| now.saturating_sub(run.at) >= target.every_secs)
                }
                OriginMirrorSyncStrategy::FullAuto => target.last.as_ref().is_none_or(|run| {
                    run.at
                        .saturating_add(ORIGIN_MIRROR_FULL_AUTO_MIN_DELAY_SECS)
                        <= now
                }),
                // An ask_me mirror switched with a plan open settles it.
                OriginMirrorSyncStrategy::AskMe => self
                    .origin_mirror_work_open(repo_id)
                    .unwrap_or_else(|error| {
                        tracing::warn!(
                            kind = ?error.kind(),
                            "a mirror's open plan could not be read"
                        );
                        false
                    }),
            };
            if !due || stop() || self.require_mirror_pusher(&target.repo).is_err() {
                report.skipped += 1;
                continue;
            }
            // The repository was renamed or recreated: its id moved, so this
            // row names a repository no longer served.
            if self.served_mirror_repo_id(&target.repo).ok() != Some(repo_id) {
                report.skipped += 1;
                continue;
            }
            let Some(_hold) = admit() else {
                report.skipped += 1;
                continue;
            };
            let trigger = match pass {
                MirrorPass::Tick => MirrorTrigger::Interval,
                MirrorPass::Wake => MirrorTrigger::Event,
            };
            match self.run_mirror_target(repo_id, &target, trigger) {
                None => report.skipped += 1,
                Some(run) if run.failure.is_some() => report.failed += 1,
                Some(_) => report.pushed += 1,
            }
        }
        Ok(report)
    }

    /// The whole-ref run of one mirror (module docs). `None` when the run
    /// had nothing to do or left the mirror for the next pass.
    pub(super) fn run_mirror_whole_refs(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
        trigger: MirrorTrigger,
    ) -> Result<Option<WholeRefsRun>> {
        let hold = mirror_hold_dir(handle)?;
        let _held = match trigger {
            MirrorTrigger::PushNow(_) => lock_repository(&hold)?,
            MirrorTrigger::Interval | MirrorTrigger::Event => match try_lock_repository(&hold)? {
                Some(held) => held,
                None => return Ok(None),
            },
        };
        let scope = MirrorRunScope {
            wire,
            handle,
            repo_id,
            target,
            hold: &hold,
        };
        let automatic = target.sync_strategy.pushes_whole_refs();
        // An open plan settles first, and a run that continued one reports
        // that plan alone: the next plan waits for a later cadence or event.
        match self.continue_mirror_plan(&scope) {
            Ok(Some(summary)) => return self.finish_mirror_run(&scope, &summary).map(Some),
            Ok(None) => {}
            Err(error) => return Err(self.hold_mirror_run(&scope, &error)),
        }
        if !automatic {
            return Ok(None);
        }
        // Read here, under the hold and after the old plan, so the newest
        // green head is what goes out.
        let Some((refs, deletions)) = self.mirror_published_basis(wire, handle, repo_id)? else {
            return Ok(None);
        };
        let selection = if target.sync_strategy == OriginMirrorSyncStrategy::FullAuto {
            self.full_auto_due(&scope, refs, deletions, trigger)?
        } else {
            Some(MirrorSelection {
                vector: refs,
                deletions,
                pending: Vec::new(),
            })
        };
        let requested_by = match trigger {
            MirrorTrigger::PushNow(owner) => owner,
            MirrorTrigger::Interval | MirrorTrigger::Event => None,
        };
        let started = match selection {
            Some(selection) => match self.start_mirror_plan(&scope, &selection, requested_by) {
                Ok(started) => started,
                Err(error) => return Err(self.hold_mirror_run(&scope, &error)),
            },
            None => None,
        };
        match started {
            Some(summary) => self.finish_mirror_run(&scope, &summary).map(Some),
            None => Ok(None),
        }
    }
}

/// The directory whose lock is one mirror's push hold, made when missing.
fn mirror_hold_dir(handle: &GitWireRepo) -> Result<PathBuf> {
    let dir = handle.common_dir().join(ORIGIN_MIRROR_HOLD_DIR);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
