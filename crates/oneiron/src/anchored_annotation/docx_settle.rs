//! Atomic managed annotation writes accompanying settled paragraph answers.

use std::collections::{BTreeMap, btree_map::Entry};

use oneiron_docedit::docx_body::read_docx_blocks;

use super::codec::{ThreadHead, annotation_envelope, encode_comment_value};
use super::comment_parts::comment_parts;
use super::{ANNOTATION_COMMENT_PREDICATE, Locator, ThreadState};
use crate::claim::ClaimSubject;
use crate::edit_roundtrip::EditProposal;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor};

impl crate::Vault {
    /// Called only after candidate verification in the existing settlement txn.
    /// Each settled paragraph judgment opens one thread at the version it was
    /// judged against, anchored on its block, with the answer as its comment —
    /// the same engine-managed thread a PPTX comment creates. The same txn's
    /// re-anchor sweep advances the new threads or records explicit
    /// unknown-anchor drift. No second settle token or standalone write path
    /// is introduced.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn apply_docx_comment_annotations_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        base_version: u64,
        proposal: &EditProposal,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let judgments = &proposal.manifest.paragraph_judgments;
        if judgments.is_empty() {
            return Ok(());
        }
        let limits = self.text_limits_in_txn(txn)?;
        // Carried answers keep the revision each was judged against, so one
        // proposal can name several judged versions; each version's blocks
        // are read once.
        // A judgment whose paragraph no longer reads as judged gets no thread:
        // the settle keeps going as it did before threads (rubric 1), and the
        // settle record's `docx_judgments` receipt still names the answer.
        let mut blocks_by_version: BTreeMap<u64, Vec<(String, String)>> = BTreeMap::new();
        for row in judgments {
            let judged = row.judged_version.unwrap_or(base_version);
            let blocks = match blocks_by_version.entry(judged) {
                Entry::Vacant(slot) => {
                    // The DOCX read runs in the host's memory (FIX 10651); a
                    // resource refusal is the engine's error (FIX 10587).
                    let resources = crate::office_body::document_resources();
                    let parsed = match self
                        .read_blob_artifact_version_in_txn(txn, artifact, judged)?
                    {
                        None => Vec::new(),
                        Some(bytes) => {
                            match resources.docx(|| read_docx_blocks(&bytes, limits.docx)) {
                                Ok(blocks) => blocks,
                                Err(error) => {
                                    if let Some(refusal) = error.resource() {
                                        return Err(crate::office_body::document_refused(refusal));
                                    }
                                    Vec::new()
                                }
                            }
                        }
                    };
                    slot.insert(
                        parsed
                            .into_iter()
                            .map(|block| (block.id, block.text))
                            .collect(),
                    )
                }
                Entry::Occupied(slot) => slot.into_mut(),
            };
            let Some(text) = blocks
                .iter()
                .find_map(|(id, text)| (*id == row.block).then_some(text))
                .filter(|text| *blake3::hash(text.as_bytes()).as_bytes() == row.text_hash)
            else {
                tracing::warn!(
                    block = %row.block,
                    version = judged,
                    "a DOCX answer opens no thread: its paragraph no longer reads as judged"
                );
                continue;
            };
            if row.comment.trim().is_empty() {
                continue;
            }
            let locator = Locator::docx(row.block.clone(), 0, text.chars().count() as u64)?;
            let thread_id = self.store.clock.entity_id()?;
            let head = ThreadHead {
                thread_id,
                origin_version: judged,
                anchor_version: judged,
                state: ThreadState::Open,
                locator,
                drift: None,
            };
            self.write_thread_head_in_txn(
                txn,
                artifact,
                &head,
                actor,
                "docx_comment",
                occurred,
                learned_at,
            )?;
            self.append_docx_annotation_in_txn(
                txn,
                artifact,
                thread_id,
                &row.comment,
                actor,
                occurred,
                learned_at,
            )?;
        }
        Ok(())
    }
    #[expect(clippy::too_many_arguments)]
    fn append_docx_annotation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        thread: EntityId,
        text: &str,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let envelope = annotation_envelope(actor, "docx_comment")?;
        // A comment past one stored body's bound lands whole as linked parts,
        // each a reply on the thread after the first.
        let mut batch = self.batch_in();
        for body in comment_parts(text) {
            batch = batch.claim_candidate(
                &EntityId::now(),
                ClaimCandidate::new(
                    ANNOTATION_COMMENT_PREDICATE,
                    ClaimSubject::Entity(*artifact),
                    encode_comment_value(&thread, &actor.entity_ref(), &body, learned_at),
                    1.0,
                ),
                &envelope,
                occurred,
                learned_at,
            );
        }
        batch.apply(txn)?;
        Ok(())
    }
}
