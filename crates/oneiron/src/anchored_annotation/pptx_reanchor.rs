//! PPTX thread re-binding over actual version bytes, including unknown-anchor drift.

use super::{AnnotationThread, Locator, ReanchorOp, ReanchorOutcome};
use crate::edit_roundtrip::pptx::{
    PptxInspection, inspect_pptx, rebind_locator, unknown_anchor_threads,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use std::collections::BTreeSet;

pub(super) struct PptxReanchor {
    before: Option<PptxInspection>,
    after: Option<PptxInspection>,
    unknown: BTreeSet<EntityId>,
}
impl PptxReanchor {
    pub(super) fn load(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        from: u64,
        to: u64,
        threads: &[AnnotationThread],
        ops: &[ReanchorOp],
    ) -> Result<Option<Self>> {
        if !threads.iter().any(|t| {
            t.anchor.version == from
                && !t.is_drifted()
                && matches!(t.anchor.locator, Locator::Pptx { .. })
        }) {
            return Ok(None);
        }
        let before_bytes = vault
            .read_blob_artifact_version_in_txn(txn, artifact, from)?
            .ok_or(Error::EntityNotFound)?;
        let after_bytes = vault
            .read_blob_artifact_version_in_txn(txn, artifact, to)?
            .ok_or(Error::EntityNotFound)?;
        let mut before = inspect_pptx(&before_bytes).ok();
        let after = inspect_pptx(&after_bytes).ok();
        // Missing or unsupported XML is unprovable: the sweep records drift,
        // never silently advances by slide number alone.
        if let (Some(before), Some(after)) = (&mut before, &after) {
            for op in ops {
                let ReanchorOp::PptxSlideCreationId { slide, creation_id } = op else {
                    continue;
                };
                let Some(old) = before
                    .slides
                    .iter_mut()
                    .find(|s| s.slide == *slide && s.creation_id.is_none())
                else {
                    continue;
                };
                if after
                    .slides
                    .iter()
                    .filter(|s| {
                        s.creation_id == Some(*creation_id)
                            && s.sld_id == old.sld_id
                            && s.part == old.part
                            && s.fingerprint == old.fingerprint
                            && s.shapes == old.shapes
                    })
                    .count()
                    == 1
                {
                    old.creation_id = Some(*creation_id);
                }
            }
        }
        let unknown = unknown_anchor_threads(&after_bytes)
            .unwrap_or_else(|_| threads.iter().map(|t| t.thread_id).collect());
        Ok(Some(Self {
            before,
            after,
            unknown,
        }))
    }
    pub(super) fn rebind(&self, thread: &AnnotationThread) -> ReanchorOutcome {
        if self.unknown.contains(&thread.thread_id) {
            return ReanchorOutcome::Drifted;
        }
        match (&self.before, &self.after) {
            (Some(before), Some(after)) => rebind_locator(&thread.anchor.locator, before, after),
            _ => ReanchorOutcome::Drifted,
        }
    }
}
