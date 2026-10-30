//! An Arc's sources as members and parts (FIX 7509 PR3, Rule 5): each
//! member's words as its calls show them, and the deterministic cut of the
//! Arc into parts that each fit one call on the model's window.
//!
//! A sitting's line shows under an `L` label with the `T` labels of the
//! TURNs it cites; a TURN read in place of a line, or opened, under its `T`
//! label; a claim under its `C` label. A member too big for a part is tiled
//! into half-open ranges with no gap and no overlap: a TURN at its MESSAGEs
//! first (each with the join before the next), then at characters; a line
//! or a claim at characters. An empty member is one empty range.
//!
//! Parts take what is left of the window beside every claim when every
//! claim fits beside the smallest piece of a line: each part is then one
//! call that reads every claim. Otherwise they take what is left beside the
//! largest claim, and claims are read in review cells beside each part's
//! own ranges. One very large claim reserves no more than
//! [`CLAIM_RESERVE_DIVISOR`]'s share of the room (FIX 8287): it is read in
//! pieces, so it never cuts every part small. No count or cap bounds a
//! part: only the window does.

use super::super::call_labels::LabelKind;
use super::super::support::invalid_consolidation;
use super::super::turn_text::TurnText;
use super::arc_evidence::ArcView;
use super::window::{escaped_cost, message_ranges, tile};
use crate::EntityId;
use crate::error::Result;
use crate::scope_summary::{
    ArcManifest, ArcMember, ArcPins, ArcRange, ArcWorkState, MemberKind, ScopeSummaryPlan,
    SummaryLineSpan, check_manifest, owned_by_parts,
};
use std::collections::BTreeMap;

/// When the claims do not all fit beside a part, the room the parts leave
/// for their review cells is the largest claim's cost, but at most the
/// spare room divided by this (FIX 8287): a claim wider than that share is
/// read in pieces, and every part keeps the rest of the room for its lines.
const CLAIM_RESERVE_DIVISOR: u64 = 2;

/// One member of an Arc's work as its calls show it.
pub(super) struct MemberText {
    pub(super) member: ArcMember,
    /// What a range of it shows under, before its words.
    head: String,
    /// What a range of it shows after its words: a line's `T` refs.
    tail: String,
    /// Its words: a line's as generated, a TURN's as read, a claim's as
    /// shown after its label.
    pub(super) text: String,
    /// The TURN it is the words of, or the TURNs a line cites.
    pub(super) turns: Vec<EntityId>,
    /// A line's recorded slices of the TURNs it cites (FIX 8289), which a
    /// part's reply citing them inherits; none for any other member.
    pub(super) spans: Vec<SummaryLineSpan>,
}

impl MemberText {
    /// How a call shows bytes `start..end` of it: nothing for an empty
    /// member.
    pub(super) fn render(&self, start: u64, end: u64) -> Result<String> {
        if self.text.is_empty() {
            return Ok(String::new());
        }
        let slice = self
            .text
            .get(start as usize..end as usize)
            .ok_or_else(|| invalid_consolidation("an arc's range is not in its member"))?;
        Ok(self.show(slice))
    }

    fn show(&self, slice: &str) -> String {
        format!("{} {slice}{}\n", self.head, self.tail)
    }

    /// The tokens bytes `start..end` of it cost where a call carries them.
    pub(super) fn cost(&self, start: u64, end: u64) -> Result<u64> {
        escaped_cost(&self.render(start, end)?)
    }

    /// The cost of its whole.
    pub(super) fn whole_cost(&self) -> Result<u64> {
        self.cost(0, self.member.len)
    }

    /// The cost of its first character alone: the least range of it.
    fn least_cost(&self) -> Result<u64> {
        let first = self.text.chars().next().map_or(0, char::len_utf8);
        self.cost(0, first as u64)
    }

    /// Its ranges, in order, each costing at most `cap`: its whole when it
    /// fits, else its tiling. `None` when one character does not fit.
    pub(super) fn tile(&self, view: &ArcView, cap: u64) -> Result<Option<Vec<(u64, u64)>>> {
        if self.whole_cost()? <= cap {
            return Ok(Some(vec![(0, self.member.len)]));
        }
        let units = self.units(view)?;
        let ranges = tile(&self.text, &units, |_, slice| {
            Ok(escaped_cost(&self.show(slice))? <= cap)
        })?;
        Ok(ranges.map(|ranges| {
            ranges
                .into_iter()
                .map(|(start, end)| (start as u64, end as u64))
                .collect()
        }))
    }

    /// Its units, in order and with no gap: a projected TURN's MESSAGEs,
    /// each with the join before the next; else its whole.
    fn units(&self, view: &ArcView) -> Result<Vec<(usize, usize)>> {
        let len = self.text.len();
        let text = match (&self.member.kind, self.turns.as_slice()) {
            (MemberKind::Fallback { .. } | MemberKind::Opened { .. }, [turn]) => view
                .texts
                .get(turn)
                .filter(|text| !text.projection().is_empty()),
            _ => None,
        };
        let Some(text) = text else {
            return Ok(vec![(0, len)]);
        };
        let mut starts: Vec<usize> = message_ranges(text, &self.text)?
            .into_iter()
            .map(|(start, _)| start)
            .collect();
        if let Some(first) = starts.first_mut() {
            *first = 0;
        }
        starts.push(len);
        starts.dedup();
        if starts.len() < 2 {
            return Ok(vec![(0, len)]);
        }
        Ok(starts.windows(2).map(|pair| (pair[0], pair[1])).collect())
    }
}

/// Each member `kinds` names, as `plan`'s Arc's calls show it from `view`.
pub(super) fn member_texts(
    plan: &ScopeSummaryPlan,
    view: &ArcView,
    kinds: Vec<MemberKind>,
) -> Result<Vec<MemberText>> {
    let arc = plan
        .arc
        .as_ref()
        .ok_or_else(|| invalid_consolidation("an arc composes from its sittings"))?;
    let mut lines = BTreeMap::new();
    for lower in &arc.lower {
        for line in &lower.lines {
            lines.insert((lower.summary.to_hex(), line.index as u32), line);
        }
    }
    let mut members = Vec::with_capacity(kinds.len());
    let mut numbered = 0_usize;
    for kind in kinds {
        let shown = match &kind {
            MemberKind::Line { summary, line } => {
                let lower = lines
                    .get(&(summary.clone(), *line))
                    .copied()
                    .ok_or_else(|| {
                        invalid_consolidation("an arc's line is not among its sources")
                    })?;
                numbered += 1;
                let refs = lower
                    .turns
                    .iter()
                    .map(|turn| turn_label(view, *turn))
                    .collect::<Result<Vec<_>>>()?;
                Shown {
                    head: format!("[L{numbered}]"),
                    tail: format!(" [{}]", refs.join(", ")),
                    words: lower.words.clone(),
                    turns: lower.turns.clone(),
                    spans: lower.source_spans.clone(),
                }
            }
            MemberKind::ReplacedBy { .. } => Shown {
                head: String::new(),
                tail: String::new(),
                words: String::new(),
                turns: Vec::new(),
                spans: Vec::new(),
            },
            MemberKind::Fallback { turn } | MemberKind::Opened { turn } => {
                turn_shown(view, EntityId::from_hex(turn)?)?
            }
            MemberKind::Claim { claim } => {
                let entry = view
                    .claim_entries
                    .iter()
                    .find(|entry| entry.id.to_hex() == *claim)
                    .ok_or_else(|| {
                        invalid_consolidation("an arc's claim is not among its sources")
                    })?;
                Shown {
                    head: format!("[{}]", entry.label),
                    tail: String::new(),
                    words: entry.body.clone(),
                    turns: Vec::new(),
                    spans: Vec::new(),
                }
            }
        };
        members.push(shown.member(kind));
    }
    Ok(members)
}

/// The member a part opens `turn` as, when no line read it in place.
pub(super) fn opened_member(view: &ArcView, turn: EntityId) -> Result<MemberText> {
    Ok(turn_shown(view, turn)?.member(MemberKind::Opened {
        turn: turn.to_hex(),
    }))
}

/// How a member shows, before it is a member.
struct Shown {
    head: String,
    tail: String,
    words: String,
    turns: Vec<EntityId>,
    spans: Vec<SummaryLineSpan>,
}

impl Shown {
    fn member(self, kind: MemberKind) -> MemberText {
        MemberText {
            member: ArcMember {
                kind,
                pin: *blake3::hash(self.words.as_bytes()).as_bytes(),
                len: self.words.len() as u64,
            },
            head: self.head,
            tail: self.tail,
            text: self.words,
            turns: self.turns,
            spans: self.spans,
        }
    }
}

/// A TURN's words as read, under its `T` label.
fn turn_shown(view: &ArcView, turn: EntityId) -> Result<Shown> {
    let words = view
        .texts
        .get(&turn)
        .and_then(TurnText::text)
        .unwrap_or_default()
        .to_owned();
    Ok(Shown {
        head: format!("[{}]", turn_label(view, turn)?),
        tail: String::new(),
        words,
        turns: vec![turn],
        spans: Vec::new(),
    })
}

fn turn_label(view: &ArcView, turn: EntityId) -> Result<String> {
    view.labels
        .label(LabelKind::Turn, turn)
        .as_ref()
        .map(ToString::to_string)
        .ok_or_else(|| invalid_consolidation("an arc's turn has no label"))
}

/// The cost of `ranges` of `members`, as one call shows them.
pub(super) fn ranges_cost(members: &[MemberText], ranges: &[ArcRange]) -> Result<u64> {
    let mut cost = 0_u64;
    for range in ranges {
        cost = cost.saturating_add(member(members, range.member)?.cost(range.start, range.end)?);
    }
    Ok(cost)
}

/// The member at `index`.
pub(super) fn member(members: &[MemberText], index: u32) -> Result<&MemberText> {
    members
        .get(index as usize)
        .ok_or_else(|| invalid_consolidation("an arc's range names no member"))
}

/// The Arc's parts on `room` tokens beside a call's frame, each the ranges
/// of lines and TURNs read in place it owns, in source order. `None` when
/// not one character of a line or TURN fits beside the frame and the
/// smallest piece of a claim.
pub(super) fn plan_groups(
    members: &[MemberText],
    view: &ArcView,
    room: u64,
) -> Result<Option<Vec<Vec<ArcRange>>>> {
    let mut floor = 0_u64;
    let mut claims = 0_u64;
    let mut largest = 0_u64;
    let mut claim_floor = 0_u64;
    for member in members {
        if owned_by_parts(&member.member.kind) {
            floor = floor.max(member.least_cost()?);
        } else if matches!(member.member.kind, MemberKind::Claim { .. }) {
            let whole = member.whole_cost()?;
            claims = claims.saturating_add(whole);
            largest = largest.max(whole);
            claim_floor = claim_floor.max(member.least_cost()?);
        }
    }
    let Some(spare) = room.checked_sub(floor) else {
        return Ok(None);
    };
    if claim_floor > spare {
        return Ok(None);
    }
    // Each part's cells take what is left beside its own ranges; the
    // reserve only keeps that room from shrinking below the largest claim,
    // or below a share of the spare room when that claim is wider (FIX 8287).
    let reserve = if claims <= spare {
        claims
    } else {
        largest.min(spare / CLAIM_RESERVE_DIVISOR).max(claim_floor)
    };
    let cap = room - reserve;
    let mut groups = Vec::new();
    let mut group = Vec::new();
    let mut cost = 0_u64;
    for (index, member) in members.iter().enumerate() {
        if !owned_by_parts(&member.member.kind) {
            continue;
        }
        let Some(ranges) = member.tile(view, cap)? else {
            return Ok(None);
        };
        for (start, end) in ranges {
            let unit = member.cost(start, end)?;
            if !group.is_empty() && cost.saturating_add(unit) > cap {
                groups.push(std::mem::take(&mut group));
                cost = 0;
            }
            group.push(ArcRange {
                member: index as u32,
                start,
                end,
            });
            cost = cost.saturating_add(unit);
        }
    }
    if !group.is_empty() {
        groups.push(group);
    }
    Ok(Some(groups))
}

/// Review cells for `ids` (claims, then TURNs a part opened), in order,
/// each holding `room` tokens at most. `None` when one character of one of
/// them does not fit: the part splits.
pub(super) fn context_cells(
    members: &[MemberText],
    view: &ArcView,
    ids: &[u32],
    room: u64,
) -> Result<Option<Vec<Vec<ArcRange>>>> {
    let mut cells = Vec::new();
    let mut cell = Vec::new();
    let mut cost = 0_u64;
    for id in ids {
        let member = member(members, *id)?;
        let Some(ranges) = member.tile(view, room)? else {
            return Ok(None);
        };
        for (start, end) in ranges {
            let unit = member.cost(start, end)?;
            if !cell.is_empty() && cost.saturating_add(unit) > room {
                cells.push(std::mem::take(&mut cell));
                cost = 0;
            }
            cell.push(ArcRange {
                member: *id,
                start,
                end,
            });
            cost = cost.saturating_add(unit);
        }
    }
    if !cell.is_empty() {
        cells.push(cell);
    }
    Ok(Some(cells))
}

/// The parts `observations` (each as a call shows it) compose in, in
/// order, each holding `room` tokens at most: one empty part when there
/// are none. `None` when one does not fit: the part splits.
pub(super) fn observation_parts(
    observations: &[String],
    room: u64,
) -> Result<Option<Vec<Vec<usize>>>> {
    let mut parts = Vec::new();
    let mut part = Vec::new();
    let mut cost = 0_u64;
    for (index, shown) in observations.iter().enumerate() {
        let unit = escaped_cost(shown)?;
        if unit > room {
            return Ok(None);
        }
        if !part.is_empty() && cost.saturating_add(unit) > room {
            parts.push(std::mem::take(&mut part));
            cost = 0;
        }
        part.push(index);
        cost = cost.saturating_add(unit);
    }
    if !part.is_empty() || parts.is_empty() {
        parts.push(part);
    }
    Ok(Some(parts))
}

/// The stored manifest `stored` goes on from, given the members the Arc's
/// sources make now: the members it opened, as shown now. `None` when it
/// was landed, read at other pins, or holds other members: a new
/// generation begins.
pub(super) fn resume_members(
    stored: &ArcManifest,
    pins: &ArcPins,
    members: &[MemberText],
    view: &ArcView,
) -> Result<Option<Vec<MemberText>>> {
    if stored.state != ArcWorkState::Open
        || stored.pins != *pins
        || check_manifest(stored).is_err()
        || stored.members.len() < members.len()
    {
        return Ok(None);
    }
    let (admitted, opened) = stored.members.split_at(members.len());
    if admitted
        .iter()
        .zip(members)
        .any(|(held, member)| *held != member.member)
    {
        return Ok(None);
    }
    let mut texts = Vec::with_capacity(opened.len());
    for held in opened {
        let MemberKind::Opened { turn } = &held.kind else {
            return Ok(None);
        };
        let Ok(turn) = EntityId::from_hex(turn) else {
            return Ok(None);
        };
        let member = opened_member(view, turn)?;
        if member.member != *held {
            return Ok(None);
        }
        texts.push(member);
    }
    Ok(Some(texts))
}

/// `ranges` in two halves that own them between them, in order: whole
/// ranges when there are two or more, else the one range cut at a
/// character near its middle. `None` for one range of one character.
pub(super) fn halve(
    ranges: &[ArcRange],
    members: &[MemberText],
) -> Option<(Vec<ArcRange>, Vec<ArcRange>)> {
    if ranges.len() >= 2 {
        let (first, second) = ranges.split_at(ranges.len() / 2);
        return Some((first.to_vec(), second.to_vec()));
    }
    let range = *ranges.first()?;
    let text = &members.get(range.member as usize)?.text;
    let (start, end) = (range.start as usize, range.end as usize);
    let least = start + text.get(start..end)?.chars().next()?.len_utf8();
    if least >= end {
        return None;
    }
    let cut = text
        .floor_char_boundary(start + (end - start) / 2)
        .max(least);
    Some((
        vec![ArcRange {
            end: cut as u64,
            ..range
        }],
        vec![ArcRange {
            start: cut as u64,
            ..range
        }],
    ))
}
