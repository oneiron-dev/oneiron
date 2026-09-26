//! Vault re-anchor sweep: the organ replays locators; the vault writes claims.

use super::codec::ThreadHead;
use super::model::{AnnotationThread, DriftMarker, ReanchorOp, ReanchorOutcome, ReanchorSummary};
use super::threads::thread_from_head;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use oneiron_docedit::anchored_annotation::replay_locator;

impl Vault {
    /// Re-anchors every live, non-drifted thread on the artifact whose anchor
    /// resolves against `from_version`, replaying `ops` (the edit-manifest for
    /// the `from_version → to_version` bump).
    ///
    /// A mappable anchor advances to `to_version` with its new locator; a
    /// non-mappable one is marked DRIFTED and stays pinned to `from_version`,
    /// never silently repositioned. Each change writes the new head and
    /// supersedes the old one in ONE write transaction, so a rejected
    /// supersession leaves that thread's original head live with no orphan.
    ///
    /// `to_version` must resolve to a real version in the artifact's chain
    /// (the same guard thread-open applies), so a replay against a not-yet-
    /// appended or bogus version writes no heads pointing at nonexistent
    /// versions.
    #[expect(clippy::too_many_arguments)]
    pub fn reanchor_annotation_threads(
        &self,
        artifact_id: &EntityId,
        from_version: u64,
        to_version: u64,
        ops: &[ReanchorOp],
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ReanchorSummary> {
        self.require_anchor_version(artifact_id, to_version)?;
        let mut summary = ReanchorSummary::default();
        for thread in self.annotation_threads_for_artifact(artifact_id)? {
            if thread.is_drifted() || thread.anchor.version != from_version {
                continue;
            }
            let (head, drifted) = plan_reanchored_head(&thread, from_version, to_version, ops);
            // Each thread's head write + old-head supersede share ONE txn, so a
            // rejected supersede leaves that thread's original head live.
            let new_head_id = self.with_write_txn(|wtxn| {
                self.apply_reanchor_head_in_txn(
                    wtxn,
                    artifact_id,
                    &thread,
                    &head,
                    actor,
                    occurred,
                    learned_at,
                )
            })?;
            push_reanchor_result(
                &mut summary,
                thread_from_head(*artifact_id, new_head_id, head),
                drifted,
            );
        }
        Ok(summary)
    }

    /// Transaction-composable re-anchor sweep: replays `ops` onto every live,
    /// non-drifted thread at `from_version`, writing all head updates through the
    /// caller's `wtxn`. ARTL-4 settle-select drives this so the re-anchor commits
    /// atomically with the version append and the consume-once ledger insert —
    /// a crash rolls the whole settle back rather than pinning threads to the old
    /// version. `to_version` is validated against the head visible in `wtxn`, so
    /// the version the same txn just appended resolves.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn reanchor_annotation_threads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        from_version: u64,
        to_version: u64,
        ops: &[ReanchorOp],
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ReanchorSummary> {
        self.require_anchor_version_in_txn(&*wtxn, artifact_id, to_version)?;
        let mut summary = ReanchorSummary::default();
        let threads = self.annotation_threads_for_artifact_in_txn(&*wtxn, artifact_id)?;
        for thread in threads {
            if thread.is_drifted() || thread.anchor.version != from_version {
                continue;
            }
            let (head, drifted) = plan_reanchored_head(&thread, from_version, to_version, ops);
            let new_head_id = self.apply_reanchor_head_in_txn(
                wtxn,
                artifact_id,
                &thread,
                &head,
                actor,
                occurred,
                learned_at,
            )?;
            push_reanchor_result(
                &mut summary,
                thread_from_head(*artifact_id, new_head_id, head),
                drifted,
            );
        }
        Ok(summary)
    }

    /// Writes one re-anchored head and supersedes the thread's prior head in the
    /// caller's txn, returning the new head claim id.
    #[expect(clippy::too_many_arguments)]
    fn apply_reanchor_head_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        thread: &AnnotationThread,
        head: &ThreadHead,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let new_head_id = self.write_thread_head_in_txn(
            wtxn,
            artifact_id,
            head,
            actor,
            "reanchor",
            occurred,
            learned_at,
        )?;
        self.supersede_claim_in_txn(wtxn, &new_head_id, &thread.head_claim_id, learned_at)?;
        Ok(new_head_id)
    }
}

/// Computes the re-anchored head for one thread across a `from → to` version
/// bump: a mappable anchor advances to `to_version` with its new locator; a
/// non-mappable one drifts and stays pinned to `from_version`. Returns the new
/// head and whether it drifted. Pure — the caller writes it.
fn plan_reanchored_head(
    thread: &AnnotationThread,
    from_version: u64,
    to_version: u64,
    ops: &[ReanchorOp],
) -> (ThreadHead, bool) {
    match replay_locator(&thread.anchor.locator, ops) {
        ReanchorOutcome::Mapped(locator) => (
            ThreadHead {
                thread_id: thread.thread_id,
                origin_version: thread.origin_version,
                anchor_version: to_version,
                state: thread.state,
                locator,
                drift: None,
            },
            false,
        ),
        ReanchorOutcome::Drifted => (
            ThreadHead {
                thread_id: thread.thread_id,
                origin_version: thread.origin_version,
                anchor_version: from_version,
                state: thread.state,
                locator: thread.anchor.locator.clone(),
                drift: Some(DriftMarker {
                    drifted_at_version: to_version,
                    pinned_version: from_version,
                }),
            },
            true,
        ),
    }
}

fn push_reanchor_result(summary: &mut ReanchorSummary, thread: AnnotationThread, drifted: bool) {
    if drifted {
        summary.drifted.push(thread);
    } else {
        summary.remapped.push(thread);
    }
}
