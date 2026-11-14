//! The escalation rows a window slot's early finish holds (FIX 21927, review
//! round 1 of #7855): each open-conflict marker and contradiction gap its
//! conflict sets left standing. That finish runs before the slot's place in
//! admission order, so these rows wait on the branch it ran on. The slot's
//! settle writes them only with a run that lands as it ran; a run that parks
//! or runs again drops them, as the serial pass would never have written
//! them. Every other branch writes them at once.

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use crate::dreamer_consolidation::gap::{GapQueueDelta, ReflectionGap};
use crate::dreamer_consolidation::{ConflictSet, KeptDecision};
use crate::{Result, Vault, WriteActor};
use oneiron_model::llm::Scope;

use super::BranchResources;

/// The escalation rows one branch holds, in the order its finish decided
/// them: each marker as its set escalated, then the gaps.
#[derive(Default)]
pub(in crate::dreamer_consolidation) struct HeldEscalations {
    conflicts: Vec<HeldConflict>,
    gaps: Vec<HeldGaps>,
}

/// One open-conflict marker, with what `park_open_conflict` writes it from.
struct HeldConflict {
    attempt: AttemptId,
    conflict: ConflictSet,
    members: Vec<VerifiedCandidate>,
    decisions: Vec<KeptDecision>,
    now: u64,
}

/// One gap upsert, with what `write_verified_gaps` writes it from.
struct HeldGaps {
    scope: Scope,
    gaps: Vec<(ReflectionGap, VerifiedEvidenceSet)>,
    now: u64,
}

impl HeldEscalations {
    /// Writes the held rows through `resources` (the branch that held them,
    /// no longer holding), in the order the finish decided them. A failed
    /// write is the run's own failure, as the finish's write would have been.
    pub(in crate::dreamer_consolidation) fn publish(
        self,
        vault: &Vault,
        actor: WriteActor,
        resources: &BranchResources<'_>,
    ) -> Result<()> {
        for held in self.conflicts {
            let members: Vec<&VerifiedCandidate> = held.members.iter().collect();
            crate::dreamer_consolidation::open_conflict::park_open_conflict(
                vault,
                actor,
                held.attempt,
                &held.conflict,
                &members,
                &held.decisions,
                &resources.write_fence(),
                held.now,
            )?;
        }
        for held in self.gaps {
            resources.write_verified_gaps(&held.scope, held.gaps, held.now)?;
        }
        Ok(())
    }
}

impl BranchResources<'_> {
    /// From here on this branch holds its escalation rows for its slot's
    /// settle instead of writing them: a window slot's early finish.
    pub(in crate::dreamer_consolidation) fn hold_escalations(&self) {
        self.held.replace(Some(HeldEscalations::default()));
    }

    /// The rows this branch held (none when it never held); from here on it
    /// writes them at once again.
    pub(in crate::dreamer_consolidation) fn take_held_escalations(&self) -> HeldEscalations {
        self.held.take().unwrap_or_default()
    }

    /// Parks `conflict` open through this branch's fence
    /// (`open_conflict::park_open_conflict`), or holds the marker while the
    /// branch holds its escalations.
    #[expect(
        clippy::too_many_arguments,
        reason = "it takes park_open_conflict's own arguments, the fence aside"
    )]
    pub(in crate::dreamer_consolidation) fn park_open_conflict(
        &self,
        vault: &Vault,
        actor: WriteActor,
        attempt: AttemptId,
        conflict: &ConflictSet,
        members: &[&VerifiedCandidate],
        decisions: &[KeptDecision],
        now: u64,
    ) -> Result<()> {
        if let Some(held) = self.held.borrow_mut().as_mut() {
            held.conflicts.push(HeldConflict {
                attempt,
                conflict: conflict.clone(),
                members: members.iter().copied().cloned().collect(),
                decisions: decisions.to_vec(),
                now,
            });
            return Ok(());
        }
        crate::dreamer_consolidation::open_conflict::park_open_conflict(
            vault,
            actor,
            attempt,
            conflict,
            members,
            decisions,
            &self.write_fence(),
            now,
        )?;
        Ok(())
    }

    /// Upserts the verified contradiction gaps into the origin's gap queue
    /// (`write_verified_gaps`), or holds them while the branch holds its
    /// escalations; a held upsert reports no change yet.
    pub(in crate::dreamer_consolidation) fn upsert_verified_gaps(
        &self,
        scope: &Scope,
        gaps: Vec<(ReflectionGap, VerifiedEvidenceSet)>,
        now: u64,
    ) -> Result<GapQueueDelta> {
        if let Some(held) = self.held.borrow_mut().as_mut() {
            held.gaps.push(HeldGaps {
                scope: scope.clone(),
                gaps,
                now,
            });
            return Ok(GapQueueDelta::default());
        }
        self.write_verified_gaps(scope, gaps, now)
    }
}
