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

use super::arc_sources::ArcSources;
use super::codec::invalid;
use super::derivation::{SummaryLineSources, SummaryLineSpan, SummarySourceVersion};
use super::request::ScopeSummaryPlan;
use crate::EntityId;
use crate::dreamer_consolidation::ScopeSummaryEvidence;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const WORK_DOMAIN: &[u8] = b"oneiron:arc-work:v1";
const RESULT_DOMAIN: &[u8] = b"oneiron:arc-work-result:v1";

/// One row of an Arc's work generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ArcWorkRow {
    Manifest(Box<ArcManifest>),
    Child(ArcChildRow),
    Reduce(ArcReduceRow),
}

/// Everything a generation was read at, in full: a resume and the landing
/// read them all again, and any change is another generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcPins {
    pub(crate) memo: [u8; 32],
    pub(crate) evidence: [u8; 32],
    pub(crate) source_set: [u8; 32],
    pub(crate) policy_frontier: [u8; 32],
    pub(crate) params_hash: [u8; 32],
    pub(crate) window: u64,
    pub(crate) sources: Vec<SummarySourceVersion>,
    pub(crate) covers: Vec<String>,
    pub(crate) messages: Vec<(String, [u8; 32])>,
}

impl ArcPins {
    /// The pins of `plan`'s Arc over `evidence`, composed under `memo` and
    /// `params_hash` on `window`.
    pub(crate) fn of(
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        memo: &[u8; 32],
        params_hash: &[u8; 32],
        window: u64,
    ) -> Result<Self> {
        let arc = plan
            .arc
            .as_ref()
            .ok_or_else(|| invalid("an arc's work pins an arc"))?;
        Ok(Self {
            memo: *memo,
            evidence: evidence.fingerprint()?,
            source_set: arc.source_set,
            policy_frontier: plan.policy_frontier,
            params_hash: *params_hash,
            window,
            sources: evidence.source_versions.clone(),
            covers: evidence.covers.iter().map(EntityId::to_hex).collect(),
            messages: evidence
                .messages
                .iter()
                .map(|message| (message.id.to_hex(), message.revision))
                .collect(),
        })
    }
}

/// What one member of a generation is, by full id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum MemberKind {
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
pub(crate) struct ArcMember {
    pub(crate) kind: MemberKind,
    pub(crate) pin: [u8; 32],
    pub(crate) len: u64,
}

/// A half-open byte range of one member's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcRange {
    pub(crate) member: u32,
    pub(crate) start: u64,
    pub(crate) end: u64,
}

/// One part of the Arc: the line and TURN ranges it owns, in source order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcChildPlan {
    pub(crate) id: u32,
    pub(crate) ranges: Vec<ArcRange>,
}

/// Whether a generation's Arc has landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ArcWorkState {
    Open,
    Published { summary: String, digest: [u8; 32] },
}

/// A generation's manifest: its pins, its members, and its parts in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcManifest {
    pub(crate) pins: ArcPins,
    pub(crate) members: Vec<ArcMember>,
    pub(crate) children: Vec<ArcChildPlan>,
    /// The id the next part replacing a split one takes.
    pub(crate) next_child: u32,
    pub(crate) state: ArcWorkState,
}

/// How a part composes: one call over its lines with every claim, or one
/// review call per cell of claims and opened words, then its lines over
/// those reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ChildMode {
    Single,
    Review,
}

/// One line a checked step wrote, as refs: the digest of its words, the
/// TURNs it cites and the slices of those shown in part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcLineRef {
    pub(crate) text: [u8; 32],
    pub(crate) turn_refs: Vec<String>,
    pub(crate) source_spans: Vec<SummaryLineSpan>,
}

/// One checked step: the attempt and request hash it settled under, the
/// model it was asked of, the digest of its reply and its lines' refs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcStepRef {
    pub(crate) attempt: [u8; 16],
    pub(crate) step: [u8; 32],
    pub(crate) model: String,
    pub(crate) reply: [u8; 32],
    pub(crate) lines: Vec<ArcLineRef>,
}

/// One part's progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcChildRow {
    pub(crate) mode: ChildMode,
    /// The TURN members this part asked opened, each read whole by it.
    pub(crate) opened: Vec<u32>,
    /// Its review cells in order: ranges of claims and opened TURNs.
    pub(crate) cells: Vec<Vec<ArcRange>>,
    /// The checked review of each cell so far, in cell order.
    pub(crate) reviewed: Vec<ArcStepRef>,
    /// Its checked lines so far, one step per part of its reviews.
    pub(crate) composed: Vec<ArcStepRef>,
    /// The parts its reviews compose in; 0 until counted.
    pub(crate) parts: u32,
    pub(crate) done: bool,
}

impl ArcChildRow {
    /// A part not yet begun, owing `opened`.
    pub(crate) fn fresh(opened: Vec<u32>) -> Self {
        Self {
            mode: ChildMode::Single,
            opened,
            cells: Vec::new(),
            reviewed: Vec::new(),
            composed: Vec::new(),
            parts: 0,
            done: false,
        }
    }
}

/// The assembly of every part: the digest of the Arc it lands and its line
/// count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArcReduceRow {
    pub(crate) digest: [u8; 32],
    pub(crate) lines: u64,
}

/// A generation's id: the Arc's stable declaration, its composition memo
/// (every evidence pin, the policy and keep, the instruction, model, output
/// contract, window and the parts' contract), its source set and policy.
pub(crate) fn work_id(
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

/// The digest of an assembled Arc: its text, its keep and every line's
/// range, refs and slices, in order.
pub(crate) fn result_digest(text: &str, keep: &str, lines: &[SummaryLineSources]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESULT_DOMAIN);
    let mut part = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    part(text.as_bytes());
    part(keep.as_bytes());
    for line in lines {
        part(&(line.output_start as u64).to_be_bytes());
        part(&(line.output_end as u64).to_be_bytes());
        for turn in &line.turn_refs {
            part(turn.as_bytes());
        }
        part(b"spans");
        for span in &line.source_spans {
            part(span.turn.as_bytes());
            part(span.message.as_deref().unwrap_or_default().as_bytes());
            part(&[u8::from(span.message.is_some())]);
            part(&(span.start as u64).to_be_bytes());
            part(&(span.end as u64).to_be_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// Every member an Arc's admitted sources make, in source order: each
/// sitting's lines in order (a whole line as itself; another as the TURNs
/// read in its place, each TURN once, then its marker), then each claim.
/// Opened TURNs follow these as parts open them.
pub(crate) fn arc_member_kinds(arc: &ArcSources, claims: &[EntityId]) -> Vec<MemberKind> {
    let mut kinds = Vec::new();
    let mut turns: BTreeMap<EntityId, u32> = BTreeMap::new();
    for lower in &arc.lower {
        let summary = lower.summary.to_hex();
        for line in &lower.lines {
            let index = line.index as u32;
            if line.whole {
                kinds.push(MemberKind::Line {
                    summary: summary.clone(),
                    line: index,
                });
                continue;
            }
            let mut members = Vec::with_capacity(line.turns.len());
            for turn in &line.turns {
                let member = *turns.entry(*turn).or_insert_with(|| {
                    kinds.push(MemberKind::Fallback {
                        turn: turn.to_hex(),
                    });
                    (kinds.len() - 1) as u32
                });
                members.push(member);
            }
            kinds.push(MemberKind::ReplacedBy {
                summary: summary.clone(),
                line: index,
                turns: members,
            });
        }
    }
    for claim in claims {
        kinds.push(MemberKind::Claim {
            claim: claim.to_hex(),
        });
    }
    kinds
}

/// Whether `kind` is owned by a part's ranges: a line or a TURN read in
/// place of one.
pub(crate) const fn owned_by_parts(kind: &MemberKind) -> bool {
    matches!(kind, MemberKind::Line { .. } | MemberKind::Fallback { .. })
}

/// Whether `kind` is a TURN's words.
pub(crate) const fn is_turn(kind: &MemberKind) -> bool {
    matches!(
        kind,
        MemberKind::Fallback { .. } | MemberKind::Opened { .. }
    )
}

/// The engine's coverage check of a manifest: each TURN owned once, each
/// marker pointing at TURN members, and the parts' ranges, in order, tiling
/// every line and TURN read in place with no gap, overlap or stray range.
pub(crate) fn check_manifest(manifest: &ArcManifest) -> Result<()> {
    let members = &manifest.members;
    let mut turns = BTreeSet::new();
    for member in members {
        match &member.kind {
            MemberKind::ReplacedBy { turns: read, .. } => {
                let fallback = |index: &u32| {
                    members
                        .get(*index as usize)
                        .is_some_and(|member| matches!(member.kind, MemberKind::Fallback { .. }))
                };
                if member.len != 0 || !read.iter().all(fallback) {
                    return Err(invalid("an arc's line marker points at no turn"));
                }
            }
            MemberKind::Fallback { turn } | MemberKind::Opened { turn } => {
                if !turns.insert(turn.as_str()) {
                    return Err(invalid("an arc's work owns a turn twice"));
                }
            }
            MemberKind::Line { .. } | MemberKind::Claim { .. } => {}
        }
    }
    let mut ids = BTreeSet::new();
    let mut cursor: BTreeMap<u32, u64> = BTreeMap::new();
    let mut last = 0_u32;
    for child in &manifest.children {
        if !ids.insert(child.id) || child.id >= manifest.next_child || child.ranges.is_empty() {
            return Err(invalid("an arc's parts are not one each"));
        }
        for range in &child.ranges {
            let member = members
                .get(range.member as usize)
                .filter(|member| owned_by_parts(&member.kind))
                .ok_or_else(|| invalid("an arc's part owns what no part reads"))?;
            if range.member < last {
                return Err(invalid("an arc's parts are out of source order"));
            }
            last = range.member;
            let first = !cursor.contains_key(&range.member);
            let at = cursor.entry(range.member).or_insert(0);
            let empty = range.end == range.start;
            if range.start != *at
                || range.end < range.start
                || range.end > member.len
                || (empty && (member.len != 0 || !first))
            {
                return Err(invalid("an arc's parts do not tile a member"));
            }
            *at = range.end;
        }
    }
    for (index, member) in members.iter().enumerate() {
        if owned_by_parts(&member.kind) && cursor.get(&(index as u32)) != Some(&member.len) {
            return Err(invalid("an arc's parts miss a member"));
        }
    }
    Ok(())
}

/// Whether `cells` show every byte of member `member`, `len` bytes long,
/// once each: an empty member as its one empty range.
pub(crate) fn cells_cover(cells: &[Vec<ArcRange>], member: u32, len: u64) -> bool {
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

/// Whether part `row` is done to the end under `manifest`: every review
/// cell and every compose part checked, every claim and every TURN it
/// opened read whole when it reviews, one call when it does not.
pub(crate) fn child_terminal(row: &ArcChildRow, manifest: &ArcManifest) -> bool {
    if !row.done || row.parts == 0 || row.composed.len() != row.parts as usize {
        return false;
    }
    let opened = row.opened.iter().all(|index| {
        manifest
            .members
            .get(*index as usize)
            .is_some_and(|member| is_turn(&member.kind))
    });
    match row.mode {
        ChildMode::Single => opened && row.cells.is_empty() && row.parts == 1,
        ChildMode::Review => {
            let read = |index: u32| {
                manifest
                    .members
                    .get(index as usize)
                    .is_some_and(|member| cells_cover(&row.cells, index, member.len))
            };
            opened
                && row.reviewed.len() == row.cells.len()
                && manifest
                    .members
                    .iter()
                    .enumerate()
                    .filter(|(_, member)| matches!(member.kind, MemberKind::Claim { .. }))
                    .all(|(index, _)| read(index as u32))
                && row.opened.iter().all(|index| read(*index))
        }
    }
}

/// Whether every pin of one id is the same version: two versions of one
/// source end the generation.
pub(crate) fn pins_consistent(sources: &[SummarySourceVersion]) -> bool {
    let mut by_id: BTreeMap<&str, &SummarySourceVersion> = BTreeMap::new();
    sources.iter().all(|pin| {
        let stored = *by_id.entry(pin.id.as_str()).or_insert(pin);
        stored == pin
    })
}
