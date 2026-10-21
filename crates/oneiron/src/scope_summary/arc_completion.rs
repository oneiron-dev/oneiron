//! An Arc never lands in part (FIX 7509 PR3). In the landing writer, before
//! anything is minted, and before an exact composition is reused, an Arc
//! composed in parts proves its generation complete: its manifest holds
//! every admitted source once, its parts tile every line and TURN read in
//! place, every part, review cell and opened turn is done, every pin is the
//! one the landing reads again, and the Arc it lands is the assembly of its
//! parts, digest for digest. An Arc written in one call is its own complete
//! manifest and passes as it is.

use super::arc_work::{
    ArcPins, ArcWorkState, MemberKind, arc_member_kinds, check_manifest, child_terminal,
    pins_consistent, result_digest,
};
use super::arc_work_store::{
    child_in_txn, manifest_in_txn, put_manifest_in_txn, reduce_in_txn, work_id_in_txn,
};
use super::codec::invalid;
use super::request::{ComposedSummary, ScopeSummaryPlan};
use crate::dreamer_consolidation::ScopeSummaryEvidence;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};

/// The completion proof at the landing of `composed` as `summary`; on
/// success its generation is marked landed in the same writer.
pub(super) fn validate_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    plan: &ScopeSummaryPlan,
    evidence: &ScopeSummaryEvidence,
    composed: &ComposedSummary<'_>,
    summary: &EntityId,
) -> Result<()> {
    let Some(arc) = &plan.arc else {
        return Ok(());
    };
    let Some(work) = composed.arc_work else {
        return Ok(());
    };
    if work != work_id_in_txn(vault, txn, plan, &composed.memo)? {
        return Err(invalid("an arc lands from another composition's work"));
    }
    let work = bytes_to_hex_lower(&work);
    let mut manifest =
        manifest_in_txn(vault, txn, &work)?.ok_or_else(|| invalid("an arc's work is gone"))?;
    if manifest.state != ArcWorkState::Open {
        return Err(invalid("an arc's work already landed"));
    }
    let pins = ArcPins::of(
        plan,
        evidence,
        &composed.memo,
        &composed.params_hash,
        manifest.pins.window,
    )?;
    if manifest.pins != pins || !pins_consistent(&evidence.source_versions) {
        return Err(invalid("an arc's work was read at other versions"));
    }
    check_manifest(&manifest)?;
    let expected = arc_member_kinds(arc, &evidence.arc_claims());
    let admitted: Vec<&MemberKind> = manifest
        .members
        .iter()
        .map(|member| &member.kind)
        .filter(|kind| !matches!(kind, MemberKind::Opened { .. }))
        .collect();
    if admitted.len() != expected.len()
        || admitted
            .iter()
            .zip(&expected)
            .any(|(held, source)| *held != source)
    {
        return Err(invalid("an arc's work does not hold every source"));
    }
    for child in &manifest.children {
        let row = child_in_txn(vault, txn, &work, child.id)?
            .ok_or_else(|| invalid("an arc's part has no record"))?;
        if !child_terminal(&row, &manifest) {
            return Err(invalid("an arc's part is not done"));
        }
    }
    let reduce = reduce_in_txn(vault, txn, &work)?
        .ok_or_else(|| invalid("an arc's parts were not assembled"))?;
    let lines = composed.line_sources.as_deref().unwrap_or_default();
    if reduce.digest != result_digest(composed.text, composed.keep, lines)
        || reduce.lines != lines.len() as u64
    {
        return Err(invalid("an arc lands other words than its parts"));
    }
    manifest.state = ArcWorkState::Published {
        summary: summary.to_hex(),
        digest: reduce.digest,
    };
    put_manifest_in_txn(vault, txn, &work, &manifest)
}

/// Whether `summary`, standing under `memo`, may be reused as `plan`'s
/// exact composition: an Arc's generation under that memo must be the one
/// that landed it, its parts still tiling its sources. With no generation
/// under the memo it was one call, its own complete manifest.
pub(super) fn reuse_complete_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    plan: &ScopeSummaryPlan,
    memo: &[u8; 32],
    summary: &EntityId,
) -> Result<bool> {
    if plan.arc.is_none() {
        return Ok(true);
    }
    let work = bytes_to_hex_lower(&work_id_in_txn(vault, txn, plan, memo)?);
    let Some(manifest) = manifest_in_txn(vault, txn, &work)? else {
        return Ok(true);
    };
    let landed = matches!(
        &manifest.state,
        ArcWorkState::Published { summary: landed, .. } if *landed == summary.to_hex()
    );
    Ok(landed && check_manifest(&manifest).is_ok())
}
