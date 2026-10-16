//! PPTX thread re-binding over actual version bytes, including unknown-anchor drift.

use super::{AnnotationThread, Locator, ReanchorOp, ReanchorOutcome};
use crate::edit_roundtrip::pptx::{
    PptxInspection, inspect_pptx_with_limits, rebind_locator, unknown_anchor_threads_with_limits,
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
        let limits = crate::gate::resolve_policy_manifest(&vault.store, txn)?
            .pptx_comment_limits()
            .ok_or(Error::Artifact(
                crate::error::ArtifactError::InvalidEditManifest(
                    "PowerPoint comment limits policy failed closed",
                ),
            ))?;
        let mut before = inspect_pptx_with_limits(&before_bytes, &limits).ok();
        let after = inspect_pptx_with_limits(&after_bytes, &limits).ok();
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
        let unknown = unknown_anchor_threads_with_limits(&after_bytes, &limits)
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
            (Some(before), Some(after)) => {
                match rebind_locator(&thread.anchor.locator, before, after) {
                    ReanchorOutcome::Drifted => {
                        identity_rebind(&thread.anchor.locator, before, after)
                    }
                    mapped => mapped,
                }
            }
            _ => ReanchorOutcome::Drifted,
        }
    }
}

/// The owner's rule for an edit inside the commented spot (OF-368,
/// 2026-10-17): a shape or slide whose creation identity survives keeps its
/// anchor even when its content changed. Only a missing or doubled identity
/// detaches; [`rebind_locator`]'s unchanged-content rebind runs first.
fn identity_rebind(
    locator: &Locator,
    before: &PptxInspection,
    after: &PptxInspection,
) -> ReanchorOutcome {
    let Locator::Pptx { slide, shape_id } = locator else {
        return ReanchorOutcome::Drifted;
    };
    let Some(old) = before.slides.iter().find(|s| s.slide == *slide) else {
        return ReanchorOutcome::Drifted;
    };
    let Some(id) = old.creation_id else {
        return ReanchorOutcome::Drifted;
    };
    let found: Vec<_> = after
        .slides
        .iter()
        .filter(|s| s.creation_id == Some(id) && s.sld_id == old.sld_id)
        .collect();
    let [new] = found.as_slice() else {
        return ReanchorOutcome::Drifted;
    };
    if shape_id == "slide" {
        return ReanchorOutcome::Mapped(Locator::Pptx {
            slide: new.slide,
            shape_id: shape_id.clone(),
        });
    }
    let key = |text: &str| {
        text.trim_matches(|c| c == '{' || c == '}')
            .to_ascii_uppercase()
    };
    let wanted = key(shape_id);
    let number = shape_id.parse::<u32>().ok();
    let old_shapes: Vec<_> = old
        .shapes
        .iter()
        .filter(|s| {
            s.creation_id.as_deref().is_some_and(|g| key(g) == wanted)
                || number == Some(s.shape_id)
        })
        .collect();
    let [old_shape] = old_shapes.as_slice() else {
        return ReanchorOutcome::Drifted;
    };
    let Some(guid) = &old_shape.creation_id else {
        return ReanchorOutcome::Drifted;
    };
    let unique = |shapes: &[crate::edit_roundtrip::pptx::PptxShapeIdentity]| {
        shapes
            .iter()
            .filter(|s| s.creation_id.as_ref() == Some(guid))
            .count()
            == 1
    };
    if !unique(&old.shapes) || !unique(&new.shapes) {
        return ReanchorOutcome::Drifted;
    }
    ReanchorOutcome::Mapped(Locator::Pptx {
        slide: new.slide,
        shape_id: guid.clone(),
    })
}
