//! An Arc composed in parts (FIX 7509 PR3, SUMMARY-SOURCE = A): an Arc
//! whose input does not fit one call on its model is one durable work
//! generation, frozen by its declaration, its pins and its call contract.
//!
//! Its manifest owns each source exactly once ([`ArcMember`]): every lower
//! line admitted whole, every TURN read in place of a line, every admitted
//! claim, and every TURN a part opened. A line that is not the Arc's whole
//! is a marker pointing at the TURN members read in its place. Each part
//! ([`ArcChildPlan`]) owns half-open byte ranges of lines and TURNs; the
//! ranges of every part, in order, tile every such member with no gap and no
//! overlap. Claims and opened TURNs are read by every part that needs them,
//! never owned twice. Coverage is the engine's check here, never a model's
//! word, at every resume and at the landing.
//!
//! Rows hold refs, pins, ranges, states and step refs: never a source's
//! words, never a model's prose.

use crate::scope_summary::codec::invalid;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const WORK_DOMAIN: &[u8] = b"oneiron:arc-work:v1";
pub const RESULT_DOMAIN: &[u8] = b"oneiron:arc-work-result:v1";

/// What one member of a generation is, by full id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberKind {
    /// A sitting's line admitted whole: its summary and its place.
    Line { summary: String, line: u32 },
    /// A sitting's line not the Arc's whole: the TURN members read in its
    /// place. It owns no bytes.
    ReplacedBy {
        summary: String,
        line: u32,
        turns: Vec<u32>,
    },
    /// A TURN read in place of a line.
    Fallback { turn: String },
    /// An admitted claim.
    Claim { claim: String },
    /// A TURN a part opened that no line read in place.
    Opened { turn: String },
}

/// One member: what it is, the digest of its words as read, and their
/// length in bytes. An empty one is a member too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcMember {
    pub kind: MemberKind,
    pub pin: [u8; 32],
    pub len: u64,
}

/// A half-open byte range of one member's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcRange {
    pub member: u32,
    pub start: u64,
    pub end: u64,
}

/// One part of the Arc: the line and TURN ranges it owns, in source order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcChildPlan {
    pub id: u32,
    pub ranges: Vec<ArcRange>,
}

/// Whether a generation's Arc has landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArcWorkState {
    Open,
    Published { summary: String, digest: [u8; 32] },
}

/// How a part composes: one call over its lines with every claim, or one
/// review call per cell of claims and opened words, then its lines over
/// those reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildMode {
    Single,
    Review,
}

/// The assembly of every part: the digest of the Arc it lands and its line
/// count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcReduceRow {
    pub digest: [u8; 32],
    pub lines: u64,
}

/// A generation's id: the Arc's stable declaration, its composition memo
/// (every evidence pin, the policy and keep, the instruction, model, output
/// contract, window and the parts' contract), its source set and policy.
pub fn work_id(
    declaration: &[u8; 32],
    memo: &[u8; 32],
    source_set: &[u8; 32],
    policy_frontier: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WORK_DOMAIN);
    hasher.update(declaration);
    hasher.update(memo);
    hasher.update(source_set);
    hasher.update(policy_frontier);
    *hasher.finalize().as_bytes()
}

/// Whether `kind` is owned by a part's ranges: a line or a TURN read in
/// place of one.
pub const fn owned_by_parts(kind: &MemberKind) -> bool {
    matches!(kind, MemberKind::Line { .. } | MemberKind::Fallback { .. })
}

/// Whether `kind` is a TURN's words.
pub const fn is_turn(kind: &MemberKind) -> bool {
    matches!(
        kind,
        MemberKind::Fallback { .. } | MemberKind::Opened { .. }
    )
}

/// Whether `cells` show every byte of member `member`, `len` bytes long,
/// once each: an empty member as its one empty range.
pub fn cells_cover(cells: &[Vec<ArcRange>], member: u32, len: u64) -> bool {
    let mut ranges: Vec<(u64, u64)> = cells
        .iter()
        .flatten()
        .filter(|range| range.member == member)
        .map(|range| (range.start, range.end))
        .collect();
    ranges.sort_unstable();
    if len == 0 {
        return ranges == [(0, 0)];
    }
    let mut at = 0;
    for (start, end) in ranges {
        if start != at || end <= start {
            return false;
        }
        at = end;
    }
    at == len
}
