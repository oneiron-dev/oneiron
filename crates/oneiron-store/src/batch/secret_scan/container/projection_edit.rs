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

use crate::batch::secret_scan::container::Budget;
use crate::batch::secret_scan::container::ContainerReadMode;
use crate::batch::secret_scan::container::Stop;
use crate::batch::secret_scan::container::Walked;
use crate::batch::secret_scan::container::retained_iterative;
use crate::batch::secret_scan::container::retained_iterative::RetainedLeafTransform;
use crate::file_secret_marks::KeyPlaces;
use crate::file_secret_marks::MemberStep;
use oneiron_base::error::Result;

/// The caller's leaf diff: one changed member's original bytes, the copy's,
/// the agent's and the spans the original's member keeps its keys at, to
/// the original's member with the edit mapped onto it; `None` when the edit
/// has no unique place.
pub type RetainedMemberDiff<'l> =
    dyn FnMut(&[u8], &[u8], &[u8], &[(u64, u64)]) -> Option<Vec<u8>> + 'l;

/// What replaying a container edit onto its original came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedProjectionEdit {
    /// The original, rebuilt with each changed member mapped onto it.
    Rebuilt(Vec<u8>),
    /// The edit has no unique place in the original.
    Unmapped,
}

/// The changed members the leaf diff maps, by path.
pub struct MemberEdits<'e, 'l> {
    /// Each changed member with no changed member under it: its path, the
    /// copy's bytes and the agent's.
    pub changed: Vec<(Vec<MemberStep>, &'e [u8], &'e [u8])>,
    pub places: &'e KeyPlaces,
    pub leaf: &'l mut RetainedMemberDiff<'l>,
    pub unmapped: bool,
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
