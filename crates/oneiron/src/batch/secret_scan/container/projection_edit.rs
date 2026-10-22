//! An agent's edit of a masked container copy, replayed member by member
//! onto its ORIGINAL (FIX 7608 slice 2b-ii-A, ASK E VisibleDiff).
//!
//! The copy a masked reader got was rebuilt from the original by the
//! retained rebuild, member for member at the same steps. So the copy's and
//! the submitted container's members are read by the same retained walk,
//! and each member the agent changed is matched to the original's member at
//! the same step: provenance, never equal placeholder contents, picks it.
//! The caller's leaf diff maps each changed member's edit onto the
//! original's; the original is then rebuilt through its own readers with
//! those members in place, every unchanged member and every byte of the
//! container's own as stored. An edit that adds, drops or reorders members,
//! or changes a container's own bytes, has no unique place in the original:
//! it is unmapped, never a whole-copy overwrite. No count, depth, byte or
//! time bound is added; the retained read's own stops are its only stops.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the projected candidate translation calls it in 2b-ii-B"
)]

use super::retained_iterative::{self, RetainedLeafTransform};
use super::{Budget, ContainerReadMode, Stop, Walked};
use crate::error::Result;
use crate::secret_custody::{KeyPlaces, MemberStep};

/// The caller's leaf diff: one changed member's original bytes, the copy's,
/// the agent's and the spans the original's member keeps its keys at, to
/// the original's member with the edit mapped onto it; `None` when the edit
/// has no unique place.
pub(crate) type RetainedMemberDiff<'l> =
    dyn FnMut(&[u8], &[u8], &[u8], &[(u64, u64)]) -> Option<Vec<u8>> + 'l;

/// What replaying a container edit onto its original came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RetainedProjectionEdit {
    /// The original, rebuilt with each changed member mapped onto it.
    Rebuilt(Vec<u8>),
    /// The edit has no unique place in the original.
    Unmapped,
}

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

/// The changed members the leaf diff maps, by path.
struct MemberEdits<'e, 'l> {
    /// Each changed member with no changed member under it: its path, the
    /// copy's bytes and the agent's.
    changed: Vec<(Vec<MemberStep>, &'e [u8], &'e [u8])>,
    places: &'e KeyPlaces,
    leaf: &'l mut RetainedMemberDiff<'l>,
    unmapped: bool,
}

impl RetainedLeafTransform for MemberEdits<'_, '_> {
    fn transform(&mut self, path: &[MemberStep], bytes: Vec<u8>) -> Walked<Vec<u8>> {
        let Some((_, copy, submitted)) = self.changed.iter().find(|(at, ..)| at.as_slice() == path)
        else {
            return Ok(bytes);
        };
        let spans = self
            .places
            .iter()
            .find(|(at, _)| at.as_slice() == path)
            .map_or(&[][..], |(_, spans)| spans.as_slice());
        let (copy, submitted): (&[u8], &[u8]) = (copy, submitted);
        match (self.leaf)(&bytes, copy, submitted, spans) {
            Some(mapped) => Ok(mapped),
            None => {
                self.unmapped = true;
                Ok(bytes)
            }
        }
    }

    fn descends(&self, path: &[MemberStep]) -> bool {
        self.changed
            .iter()
            .any(|(at, ..)| at.len() > path.len() && at.starts_with(path))
    }

    fn reaches(&self, path: &[MemberStep]) -> bool {
        self.changed.iter().any(|(at, ..)| at.starts_with(path))
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
