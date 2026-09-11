//! Vault CRUD: thread lifecycle, comments, brief assignment, and the
//! txn-composable read cohort.

use super::codec::{
    ThreadHead, annotation_envelope, decode_brief_value, decode_comment, decode_thread_head,
    encode_brief_value, encode_comment_value, encode_thread_head_value, is_annotation_predicate,
    task_role_body, warn_malformed_annotation_claim,
};
use super::model::{
    ANNOTATION_BRIEF_PREDICATE, ANNOTATION_COMMENT_PREDICATE, ANNOTATION_COMMENT_TEXT_MAX_BYTES,
    ANNOTATION_THREAD_PREDICATE, Anchor, AnnotationComment, AnnotationThread, TaskBrief,
    ThreadState,
};
use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::ArtifactError;
use crate::error::{Error, Result};
use crate::habit::TaskRole;
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor};

/// Weight for the `AssignedTo` / `Mentions` edge a brief writes.
const BRIEF_ASSIGN_EDGE_WEIGHT: f32 = 1.0;

// ---------------------------------------------------------------------------
// Vault surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Opens an anchored-comment thread with its first comment.
    ///
    /// Writes the thread head and the opening comment as CLAIMs on the blob
    /// artifact entity in one transaction. The anchor version must resolve to a
    /// real version in the artifact's chain.
    pub fn open_annotation_thread(
        &self,
        anchor: &Anchor,
        author: WriteActor,
        first_comment: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationThread> {
        self.require_anchor_version(&anchor.artifact_id, anchor.version)?;
        validate_comment_text(first_comment)?;

        let thread_id = EntityId::now();
        let head_claim_id = EntityId::now();
        let comment_claim_id = EntityId::now();
        let head = ThreadHead {
            thread_id,
            origin_version: anchor.version,
            anchor_version: anchor.version,
            state: ThreadState::Open,
            locator: anchor.locator.clone(),
            drift: None,
        };
        let head_envelope = annotation_envelope(author, "open_thread")?;
        let comment_envelope = annotation_envelope(author, "comment")?;
        let author_id = author.entity_ref();

        self.with_write_txn(|wtxn| {
            self.batch_in()
                .claim_candidate(
                    &head_claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_THREAD_PREDICATE,
                        ClaimSubject::Entity(anchor.artifact_id),
                        encode_thread_head_value(&head),
                        1.0,
                    ),
                    &head_envelope,
                    occurred,
                    learned_at,
                )
                .claim_candidate(
                    &comment_claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_COMMENT_PREDICATE,
                        ClaimSubject::Entity(anchor.artifact_id),
                        encode_comment_value(&thread_id, &author_id, first_comment, learned_at),
                        1.0,
                    ),
                    &comment_envelope,
                    occurred,
                    learned_at,
                )
                .apply(wtxn)
        })?;

        Ok(AnnotationThread {
            thread_id,
            anchor: anchor.clone(),
            origin_version: anchor.version,
            state: ThreadState::Open,
            drift: None,
            head_claim_id,
        })
    }

    /// Appends a comment to an existing thread.
    pub fn add_annotation_comment(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        author: WriteActor,
        text: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationComment> {
        validate_comment_text(text)?;
        // Fail closed if the thread does not exist for this artifact.
        self.get_annotation_thread(artifact_id, thread_id)?
            .ok_or(Error::Artifact(ArtifactError::AnnotationThreadNotFound))?;

        let claim_id = EntityId::now();
        let envelope = annotation_envelope(author, "comment")?;
        let author_id = author.entity_ref();
        self.with_write_txn(|wtxn| {
            self.batch_in()
                .claim_candidate(
                    &claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_COMMENT_PREDICATE,
                        ClaimSubject::Entity(*artifact_id),
                        encode_comment_value(thread_id, &author_id, text, learned_at),
                        1.0,
                    ),
                    &envelope,
                    occurred,
                    learned_at,
                )
                .apply(wtxn)
        })?;

        Ok(AnnotationComment {
            thread_id: *thread_id,
            author: author_id,
            text: text.to_owned(),
            at: learned_at,
            claim_id,
        })
    }

    /// Transitions a thread's lifecycle state (open ⇄ resolved) by superseding
    /// its head with an updated head claim.
    ///
    /// The new head write and the old head supersession share ONE write
    /// transaction, so if the supersession's fail-closed guards reject (e.g. an
    /// agent claim trying to supersede human-stated truth) nothing persists —
    /// the original head stays the single live head and no orphan claim is left
    /// behind.
    pub fn set_annotation_thread_state(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        state: ThreadState,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationThread> {
        let thread = self
            .get_annotation_thread(artifact_id, thread_id)?
            .ok_or(Error::Artifact(ArtifactError::AnnotationThreadNotFound))?;
        let head = ThreadHead {
            thread_id: *thread_id,
            origin_version: thread.origin_version,
            anchor_version: thread.anchor.version,
            state,
            locator: thread.anchor.locator.clone(),
            drift: thread.drift,
        };
        let new_head_id = self.with_write_txn(|wtxn| {
            let new_head_id = self.write_thread_head_in_txn(
                wtxn,
                artifact_id,
                &head,
                actor,
                "set_state",
                occurred,
                learned_at,
            )?;
            self.supersede_claim_in_txn(wtxn, &new_head_id, &thread.head_claim_id, learned_at)?;
            Ok(new_head_id)
        })?;
        Ok(AnnotationThread {
            thread_id: *thread_id,
            anchor: thread.anchor,
            origin_version: thread.origin_version,
            state,
            drift: thread.drift,
            head_claim_id: new_head_id,
        })
    }

    /// Reads a single thread head, or `None` if no live thread with that id is
    /// anchored on the artifact.
    pub fn get_annotation_thread(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Option<AnnotationThread>> {
        let mut best: Option<(EntityId, ThreadHead)> = None;
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_THREAD_PREDICATE {
                continue;
            }
            let head = match decode_thread_head(&body.value) {
                Ok(head) => head,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            if head.thread_id != *thread_id {
                continue;
            }
            // Newest head (by UUIDv7 id) wins, so a torn supersede that left two
            // Active heads still resolves to the latest write.
            if best.as_ref().is_none_or(|(id, _)| claim_id > *id) {
                best = Some((claim_id, head));
            }
        }
        Ok(best.map(|(claim_id, head)| thread_from_head(*artifact_id, claim_id, head)))
    }

    /// Lists all live thread heads anchored on an artifact.
    pub fn annotation_threads_for_artifact(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<AnnotationThread>> {
        Ok(threads_from_active_claims(
            *artifact_id,
            self.active_annotation_claims(artifact_id)?,
        ))
    }

    /// Transaction-composable [`Vault::annotation_threads_for_artifact`]: reads
    /// the live thread heads through the caller's txn (settle's re-anchor sweep).
    pub(super) fn annotation_threads_for_artifact_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> Result<Vec<AnnotationThread>> {
        Ok(threads_from_active_claims(
            *artifact_id,
            self.active_annotation_claims_in_txn(rtxn, artifact_id)?,
        ))
    }

    /// Reads a thread's comments, ordered by authored time then claim id.
    pub fn annotation_thread_comments(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Vec<AnnotationComment>> {
        let mut comments = Vec::new();
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_COMMENT_PREDICATE {
                continue;
            }
            let comment = match decode_comment(&body.value, claim_id) {
                Ok(comment) => comment,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            if comment.thread_id != *thread_id {
                continue;
            }
            comments.push(comment);
        }
        comments.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.claim_id.cmp(&b.claim_id)));
        Ok(comments)
    }

    /// Converts a thread into a task-brief (OF-368 D4).
    ///
    /// Writes a productivity `TASK` entity, a durable `annotation.brief` claim
    /// linking the thread to that task with the anchor payload, and — when an
    /// assignee is supplied — an `AssignedTo` edge. Returns the assembled brief
    /// carrying the anchor, the thread transcript, and the `artifact@version`.
    ///
    /// The transcript snapshot taken at assignment time is persisted IN the
    /// brief claim value, so the handed-off brief is stable: comments appended
    /// after the assignment do not change what
    /// [`Vault::annotation_brief_for_thread`] reconstructs.
    pub fn assign_annotation_thread_to_brief(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        assignee: Option<EntityId>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<TaskBrief> {
        let thread = self
            .get_annotation_thread(artifact_id, thread_id)?
            .ok_or(Error::Artifact(ArtifactError::AnnotationThreadNotFound))?;
        let comments = self.annotation_thread_comments(artifact_id, thread_id)?;
        let thread_text = comments
            .iter()
            .map(|comment| comment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let task_id = EntityId::now();
        let brief_claim_id = EntityId::now();
        let brief_ref = format!("brief:{}", thread_id.to_hex());
        let task_body = task_role_body(TaskRole::Task)?;
        let brief_envelope = annotation_envelope(actor, "assign_brief")?;
        let brief_value = encode_brief_value(
            thread_id,
            &task_id,
            &brief_ref,
            thread.anchor.version,
            &thread.anchor.locator,
            assignee.as_ref(),
            &thread_text,
        );

        self.with_write_txn(|wtxn| {
            let mut batch = self
                .batch_in()
                .put(&task_id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body)
                .claim_candidate(
                    &brief_claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_BRIEF_PREDICATE,
                        ClaimSubject::Entity(*artifact_id),
                        brief_value,
                        1.0,
                    ),
                    &brief_envelope,
                    occurred,
                    learned_at,
                );
            if let Some(assignee_id) = assignee {
                batch = batch.edge(
                    &task_id,
                    EdgeKind::AssignedTo,
                    &assignee_id,
                    BRIEF_ASSIGN_EDGE_WEIGHT,
                );
            }
            batch.apply(wtxn)
        })?;

        let artifact_version = thread.anchor.version;
        Ok(TaskBrief {
            brief_ref,
            task_id,
            thread_id: *thread_id,
            anchor: thread.anchor,
            artifact_version,
            thread_text,
            assignee,
        })
    }

    /// Reconstructs the durable brief for `thread_id` from its persisted
    /// `annotation.brief` claim, or `None` if the thread was never assigned.
    ///
    /// The returned brief carries the transcript snapshot captured at
    /// assignment time (stored in the claim value), so it is stable against
    /// comments appended after the assignment — the handed-off ask does not
    /// silently rewrite itself. When a thread was assigned more than once the
    /// newest brief (by UUIDv7 claim id) wins.
    pub fn annotation_brief_for_thread(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Option<TaskBrief>> {
        let mut best: Option<(EntityId, TaskBrief)> = None;
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_BRIEF_PREDICATE {
                continue;
            }
            let brief = match decode_brief_value(&body.value, *artifact_id) {
                Ok(brief) => brief,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            if brief.thread_id != *thread_id {
                continue;
            }
            if best.as_ref().is_none_or(|(id, _)| claim_id > *id) {
                best = Some((claim_id, brief));
            }
        }
        Ok(best.map(|(_, brief)| brief))
    }

    /// Writes a fresh thread-head claim inside the caller's write transaction
    /// and returns its id. Kept txn-composable (rather than opening its own
    /// txn) so the head write and the paired [`Vault::supersede_claim_in_txn`]
    /// of the old head commit or roll back together.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn write_thread_head_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        head: &ThreadHead,
        actor: WriteActor,
        op: &'static str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let claim_id = EntityId::now();
        let envelope = annotation_envelope(actor, op)?;
        let value = encode_thread_head_value(head);
        self.batch_in()
            .claim_candidate(
                &claim_id,
                ClaimCandidate::new(
                    ANNOTATION_THREAD_PREDICATE,
                    ClaimSubject::Entity(*artifact_id),
                    value,
                    1.0,
                ),
                &envelope,
                occurred,
                learned_at,
            )
            .apply(wtxn)?;
        Ok(claim_id)
    }

    pub(super) fn require_anchor_version(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        self.require_anchor_version_in_txn(&rtxn, artifact_id, version)
    }

    /// Transaction-composable [`Vault::require_anchor_version`]: validates the
    /// target version against the artifact head read through the caller's txn,
    /// so settle sees the version it just appended in the same write txn.
    pub(super) fn require_anchor_version_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<()> {
        if version == 0 {
            return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                "anchor version must be at least 1",
            )));
        }
        let head =
            crate::blob_artifact::read_blob_artifact_head_in_txn(&self.store, rtxn, artifact_id)?
                .ok_or(Error::Artifact(ArtifactError::InvalidAnchor(
                "anchor artifact has no versions",
            )))?;
        if version > head.version {
            return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                "anchor version is beyond the artifact head",
            )));
        }
        Ok(())
    }

    /// The live-read cohort of annotation claims on `artifact_id`: only claims
    /// that pass the engine's standard read gate
    /// ([`crate::claim::claim_surfaceable`] — `appr ∈ {auto, approved}`,
    /// `life = active`, not stale).
    ///
    /// Gating here (rather than on bare `life = active`) keeps agent-authored
    /// `Proposed` heads and stale claims out of every live read that flows
    /// through this helper — thread + comment reads, brief assignment, and
    /// newest-head selection — so a non-admitted head can never override an
    /// admitted one on read. History / consent-review still goes through the
    /// ungated [`crate::Vault::get_claim`] door.
    fn active_annotation_claims(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let rtxn = self.store.env.read_txn()?;
        self.active_annotation_claims_in_txn(&rtxn, artifact_id)
    }

    /// Transaction-composable [`Vault::active_annotation_claims`]: reads the
    /// live-read annotation cohort through the caller's txn, so settle can gather
    /// threads inside the same write txn that appends the version.
    fn active_annotation_claims_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut out = Vec::new();
        for claim_id in self.claims_for_subject_in_txn(rtxn, artifact_id)? {
            let Some(body) = self.get_claim_in_txn(rtxn, &claim_id)? else {
                continue;
            };
            if crate::claim::claim_surfaceable(&body) && is_annotation_predicate(&body.predicate) {
                out.push((claim_id, body));
            }
        }
        Ok(out)
    }
}

/// Groups a live-read annotation claim cohort into one [`AnnotationThread`] per
/// thread id (newest Active head wins on a torn supersede), skipping non-thread
/// predicates and malformed heads. Shared by the own-txn and in-txn listers.
pub(super) fn threads_from_active_claims(
    artifact_id: EntityId,
    claims: Vec<(EntityId, ClaimBody)>,
) -> Vec<AnnotationThread> {
    let mut heads: Vec<(EntityId, EntityId, ThreadHead)> = Vec::new();
    for (claim_id, body) in claims {
        if body.predicate != ANNOTATION_THREAD_PREDICATE {
            continue;
        }
        let head = match decode_thread_head(&body.value) {
            Ok(head) => head,
            Err(err) => {
                warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                continue;
            }
        };
        match heads.iter_mut().find(|(tid, _, _)| *tid == head.thread_id) {
            Some((_, existing_id, existing_head)) if claim_id > *existing_id => {
                *existing_id = claim_id;
                *existing_head = head;
            }
            Some(_) => {}
            None => heads.push((head.thread_id, claim_id, head)),
        }
    }
    let mut threads: Vec<AnnotationThread> = heads
        .into_iter()
        .map(|(_, claim_id, head)| thread_from_head(artifact_id, claim_id, head))
        .collect();
    threads.sort_by_key(|thread| thread.thread_id);
    threads
}

pub(super) fn thread_from_head(
    artifact_id: EntityId,
    head_claim_id: EntityId,
    head: ThreadHead,
) -> AnnotationThread {
    AnnotationThread {
        thread_id: head.thread_id,
        anchor: Anchor {
            artifact_id,
            version: head.anchor_version,
            locator: head.locator,
        },
        origin_version: head.origin_version,
        state: head.state,
        drift: head.drift,
        head_claim_id,
    }
}

fn validate_comment_text(text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAnchor(
            "comment text must be non-empty",
        )));
    }
    if text.len() > ANNOTATION_COMMENT_TEXT_MAX_BYTES {
        return Err(Error::Artifact(ArtifactError::InvalidAnchor(
            "comment text is too long",
        )));
    }
    Ok(())
}
