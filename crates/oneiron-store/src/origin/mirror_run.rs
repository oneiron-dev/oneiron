//! One automatic whole-ref run of one mirror, and the passes over every
//! mirror (FIX 6866 part 2).
//!
//! A run takes the mirror's own push hold, never the repository's
//! coordinator: inbound pushes, landings and cutovers never wait on an
//! outbound child, and the child inherits the hold, so one that outlives a
//! crashed host keeps the mirror held until it exits. An exact publish takes
//! the same hold, so it and a run never reach one mirror at once. An
//! interval or event run finds the hold taken and leaves the mirror for the
//! next pass; a push-now waits for it. Under the hold the mirror's open
//! plan settles first (`publish::mirror_plan_run`), and a run that continued
//! one reports that plan alone: the next plan is frozen at a later cadence
//! or event (`full_auto`: the next wake or tick). Only a mirror with no open plan
//! reads its published refs and deletions, there, under the hold, and
//! freezes a new one. A `schedule` run plans exactly the selection the
//! scheduled mirror always pushed. A `full_auto` run plans its green selection
//! (`mirror_auto`) only when it differs from the plan it settled last, or a
//! push-now asks. An `ask_me` mirror only settles a plan left open when it
//! was switched: its unsent batches are paused, never sent. A run that
//! fails before egress is held: nothing goes out, the mirror row shows
//! `review_unavailable`, and the next run reviews again from scratch.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use crate::git_wire::repo::try_lock_repository;
use crate::origin::mirror::OriginMirrorPushes;
use crate::origin::mirror::OriginMirrorTarget;
use crate::origin::mirror_auto::ORIGIN_MIRROR_FULL_AUTO_MIN_DELAY_SECS;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;
use crate::origin::publish::mirror_plan::MirrorSelection;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The directory, inside the repository's object store, whose lock is one
/// mirror's push hold: never the repository's own coordinator.
const ORIGIN_MIRROR_HOLD_DIR: &str = "oneiron-mirror-push";

/// What started a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorTrigger {
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
    pub fn records_idle(self, strategy: OriginMirrorSyncStrategy) -> bool {
        matches!(self, Self::PushNow(_)) || strategy == OriginMirrorSyncStrategy::Schedule
    }
}

/// What one pass looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorPass {
    /// Every due `schedule` mirror, every `full_auto` one, every open plan.
    Tick,
    /// Every `full_auto` mirror and every open plan; no cadence.
    Wake,
}

/// A whole-ref run that landed: its counts, the names the mirror now holds
/// from this vault, and the refs the census reads.
pub struct WholeRefsRun {
    pub refs: u64,
    pub deleted: u64,
    pub names: Vec<String>,
    pub census: Vec<(GitRefName, GitOid)>,
}

/// The directory whose lock is one mirror's push hold, made when missing.
/// An exact publish takes the same hold (`publish::dispatch`).
pub fn mirror_hold_dir(handle: &GitWireRepo) -> Result<PathBuf> {
    let dir = handle.common_dir().join(ORIGIN_MIRROR_HOLD_DIR);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
