//! Core half of `batch::secret_scan::container::projection_edit`: its store-layer items live in `oneiron_store::batch::secret_scan::container::projection_edit` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the projected candidate translation calls it in 2b-ii-B"
)]

pub(crate) use oneiron_store::batch::secret_scan::container::projection_edit::*;

use super::retained_iterative::{self, RetainedLeafTransform};
use super::{Budget, ContainerReadMode, Stop, Walked};
use crate::error::Result;
use crate::file_secret_marks::{KeyPlaces, MemberStep};

/// The members a retained read finds under `bytes`, each with its path, in
/// walk order; `None` when the walk stops on a container no reader reads.
fn members_of(bytes: &[u8]) -> Result<Option<Vec<(Vec<MemberStep>, Vec<u8>)>>> {
    let mut members = Vec::new();
    let mut budget = Budget::of(ContainerReadMode::RetainedRepo);
    let mut visit = |path: &[MemberStep], member: &[u8]| -> Walked<()> {
        members.push((path.to_vec(), member.to_vec()));
        Ok(())
    };
    match retained_iterative::walk(bytes, &mut budget, &mut visit) {
        Ok(()) => Ok(Some(members)),
        Err(Stop::Refuse(_)) => Ok(None),
        Err(Stop::Fail(error)) => Err(error),
    }
}

/// The agent's `submitted` edit of `copy`, the masked container copy of
/// `original` whose keys `places` names, replayed onto `original` member by
/// member: `leaf` maps each changed member's edit, `None` when it has no
/// unique place. A walk stop, a changed member set, a container whose own
/// bytes changed or any unmapped member is [`RetainedProjectionEdit::Unmapped`].
///
/// # Errors
/// An engine failure in a reader.
pub(crate) fn apply_retained_repo_projection_diff<'l>(
    original: &[u8],
    copy: &[u8],
    submitted: &[u8],
    places: &KeyPlaces,
    leaf: &'l mut RetainedMemberDiff<'l>,
) -> Result<RetainedProjectionEdit> {
    let (Some(copied), Some(edited)) = (members_of(copy)?, members_of(submitted)?) else {
        return Ok(RetainedProjectionEdit::Unmapped);
    };
    if copied.len() != edited.len()
        || copied
            .iter()
            .zip(&edited)
            .any(|((copy_at, _), (edit_at, _))| copy_at != edit_at)
    {
        return Ok(RetainedProjectionEdit::Unmapped);
    }
    let differs: Vec<&Vec<MemberStep>> = copied
        .iter()
        .zip(&edited)
        .filter(|((_, copy), (_, edit))| copy != edit)
        .map(|((at, _), _)| at)
        .collect();
    let mut changed = Vec::new();
    for ((at, copy), (_, edit)) in copied.iter().zip(&edited) {
        if copy == edit {
            continue;
        }
        let under = differs
            .iter()
            .any(|other| other.len() > at.len() && other.starts_with(at));
        if !under {
            changed.push((at.clone(), copy.as_slice(), edit.as_slice()));
        }
    }
    // A container's own bytes changed with no member changed under it: the
    // edit has no member to land in.
    if changed
        .iter()
        .any(|(_, copy, _)| super::kind(copy).is_some())
    {
        return Ok(RetainedProjectionEdit::Unmapped);
    }
    if changed.is_empty() {
        return Ok(RetainedProjectionEdit::Unmapped);
    }
    let mut edits = MemberEdits {
        changed,
        places,
        leaf,
        unmapped: false,
    };
    let mut budget = Budget::of(ContainerReadMode::RetainedRepo);
    match retained_iterative::rebuild_with(original, &mut edits, &mut budget) {
        Ok(rebuilt) if !edits.unmapped => Ok(RetainedProjectionEdit::Rebuilt(rebuilt)),
        Ok(_) | Err(Stop::Refuse(_)) => Ok(RetainedProjectionEdit::Unmapped),
        Err(Stop::Fail(error)) => Err(error),
    }
}
