//! Ranked prep-pack assembly under the word ceiling.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::wake::{PrepEvent, PrepPolicy, prep_is_eligible};
use crate::calendar::claims::is_calendar_claim_predicate;
use crate::context_pack::ContextEntity;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ppr::MAX_PPR_SEEDS;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_FACET, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_NOTE, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::vault::Vault;

/// Default ceiling on the assembled pack. A ceiling, not a target.
pub const DEFAULT_PREP_MAX_WORDS: usize = 250;

/// Hop budget for the scoped assembly walk around the EVENT and its attendees.
const PREP_CONTEXT_EDGE_HOP: u32 = 3;

/// Candidate ceiling handed to the retrieval. Ranking and the word budget cut
/// this down further; the cap only keeps one meeting's assembly bounded.
const PREP_CONTEXT_CANDIDATE_LIMIT: usize = 64;

/// Entity types the prep assembly is scoped to, in [`PrepSectionKind`] order.
///
/// EVENT is deliberately absent: the meeting itself is a seed, not evidence
/// about the meeting.
const PREP_CONTEXT_ENTITY_TYPES: [u8; 9] = [
    ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_TURN,
    ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_CONVERSATION,
    ENTITY_TYPE_PERSON,
    ENTITY_TYPE_ORG,
    ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_FACET,
    ENTITY_TYPE_NOTE,
];

/// Hydrated-field keys that carry an entity's own text, most specific first.
///
/// Mirrors the private alias list `context_pack.rs` uses for the same job. The
/// list is duplicated rather than exported: widening that module's API is a
/// non-claim here, and a four-entry constant is cheaper than a shared hook
/// nobody else has asked for yet.
const PREP_CONTEXT_TEXT_FIELD_ALIASES: [&str; 4] = ["val", "txt", "text", "body"];

/// Hydrated-field key carrying a CLAIM row's predicate.
const PREP_CLAIM_PREDICATE_FIELD: &str = "pred";

/// Nesting bound for the text-leaf search over one hydrated field value.
const PREP_TEXT_LEAF_MAX_DEPTH: u32 = 8;

/// The fixed section order. Declaration order in [`PrepSectionKind`] is the
/// precedence rule; this array is the same rule as data, so assembly walks it
/// instead of re-deriving it.
const PREP_SECTION_ORDER: [PrepSectionKind; 3] = [
    PrepSectionKind::PriorCommitment,
    PrepSectionKind::AttendeeThread,
    PrepSectionKind::DossierDelta,
];

/// The three ranked sections of a prep pack.
///
/// Declaration order IS the precedence rule, and `Ord` is derived from it: prior
/// commitments first, recent threads with those people second, dossier or
/// company delta third.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrepSectionKind {
    /// Commitments involving the meeting or its attendees.
    PriorCommitment,
    /// Recent threads with the people in the meeting.
    AttendeeThread,
    /// Dossier or company delta about those people and their orgs.
    DossierDelta,
}

/// Which section one stored entity type belongs to, or `None` when it carries
/// no prep meaning.
///
/// The CMT-3 swap point: today a CLAIM row is the closest thing the vault has to
/// a recorded commitment, so it takes the top section. When commitment machinery
/// lands, this arm keys on commitment rows and the rest of the module is
/// untouched.
const fn prep_section_kind_for(entity_type: u8) -> Option<PrepSectionKind> {
    match entity_type {
        ENTITY_TYPE_CLAIM => Some(PrepSectionKind::PriorCommitment),
        ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE | ENTITY_TYPE_CONVERSATION => {
            Some(PrepSectionKind::AttendeeThread)
        }
        ENTITY_TYPE_PERSON | ENTITY_TYPE_ORG | ENTITY_TYPE_SUMMARY | ENTITY_TYPE_FACET
        | ENTITY_TYPE_NOTE => Some(PrepSectionKind::DossierDelta),
        _ => None,
    }
}

/// One row of prep evidence, with the vault rows that back it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepItem {
    /// Which section this row ranks into.
    pub kind: PrepSectionKind,
    /// The row's own text, as stored. Truncated only by the word ceiling.
    pub text: String,
    /// Hex ids of the vault rows this text came from. Never empty.
    pub source_refs: Vec<String>,
    /// When the vault learned the backing row, unix seconds UTC.
    pub observed_at: u64,
}

/// One ranked section of a pack. Empty sections are dropped, never rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepSection {
    /// Which section this is.
    pub kind: PrepSectionKind,
    /// Rows, most recently learned first inside the section.
    pub items: Vec<PrepItem>,
}

/// One meeting's assembled prep pack.
///
/// Structured data only: no prose, no persona, no localized text. It is a value
/// returned to the caller and never an entity, a claim, or a cache row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepPack {
    /// Hex id of the EVENT this pack is about.
    pub event_ref: String,
    /// The fire instant the pack was assembled at, unix seconds UTC.
    pub built_at: u64,
    /// Ranked sections, never empty when a pack exists at all.
    pub sections: Vec<PrepSection>,
    /// Words kept after the ceiling. Never above [`PrepPolicy::max_words`].
    pub word_count: usize,
}

/// One assembly request: the EVENT, the instant it is being assembled at, and
/// the policy that scopes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepBuildRequest {
    /// The EVENT, as the caller re-read it at fire time.
    pub event: PrepEvent,
    /// The instant the host says the wake fired, unix seconds UTC.
    pub fired_at: u64,
    /// Eligibility, ceiling, and lead.
    pub policy: PrepPolicy,
}

/// Assembles one prep pack from live vault state at `fired_at`.
///
/// `Ok(None)` means deliberately blank — the EVENT stopped being eligible, or
/// scoping and ranking left nothing worth saying. It is never an error and never
/// an empty pack; the caller renders nothing.
///
/// The order below is load-bearing:
///
/// 1. recheck eligibility at fire time, since the EVENT may have changed since
///    the wake was planned;
/// 2. assemble scoped live context seeded on the EVENT and its attendees,
///    bounded to state the vault had learned by `fired_at`;
/// 3. materialize rows with their source refs;
/// 4. rank by section, then by recency inside the section;
/// 5. spend the word ceiling top-down, without reordering;
/// 6. answer `None` rather than pad.
///
/// # Errors
///
/// Storage and retrieval errors from the context assembly propagate unchanged.
pub fn build_prep_pack(vault: &Vault, request: &PrepBuildRequest) -> Result<Option<PrepPack>> {
    if !prep_is_eligible(&request.event, request.policy) {
        return Ok(None);
    }
    let candidates = prep_context_candidates(vault, &request.event, request.fired_at)?;
    let items = prep_items_from_candidates(vault, &request.event, &candidates)?;
    Ok(assemble_prep_pack(
        &request.event,
        request.fired_at,
        request.policy,
        items,
    ))
}

/// Runs the scoped live assembly around one EVENT.
///
/// Seeded on the EVENT and its attendees, walked over the ordinary retrieval
/// graph, narrowed to the entity types the three sections read, and — the part
/// that makes this render-time rather than replayed — bounded to rows the vault
/// had already learned at `fired_at`. Nothing here is cached: two assemblies at
/// two instants legitimately answer differently.
fn prep_context_candidates(
    vault: &Vault,
    event: &PrepEvent,
    fired_at: u64,
) -> Result<Vec<ContextEntity>> {
    let mut seeds = Vec::with_capacity(1 + event.attendee_refs.len());
    seeds.push(event.event_ref);
    for attendee in &event.attendee_refs {
        if seeds.len() >= MAX_PPR_SEEDS {
            break;
        }
        if !seeds.contains(attendee) {
            seeds.push(*attendee);
        }
    }

    let pack = vault
        .context_pack()
        .search_ppr(&seeds, PREP_CONTEXT_EDGE_HOP)
        .filter_types(&PREP_CONTEXT_ENTITY_TYPES)
        .filter_learned_range(0, fired_at)
        .limit(PREP_CONTEXT_CANDIDATE_LIMIT)
        .run()?;

    let mut candidates = pack.results;
    candidates.extend(pack.neighbors);
    Ok(candidates)
}

/// Turns assembled candidates into ranked rows, dropping everything that says
/// nothing: the seeds themselves, duplicates, redirect and deleted shells,
/// types outside the three sections, and rows with no readable text.
fn prep_items_from_candidates(
    vault: &Vault,
    event: &PrepEvent,
    candidates: &[ContextEntity],
) -> Result<Vec<(EntityId, PrepItem)>> {
    let mut seen: HashSet<EntityId> = HashSet::with_capacity(candidates.len());
    let mut items = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.id == event.event_ref || event.attendee_refs.contains(&candidate.id) {
            continue;
        }
        if !seen.insert(candidate.id) {
            continue;
        }
        let Some(kind) = prep_section_kind_for(candidate.entity_type) else {
            continue;
        };
        let Some(fields) = candidate.fields.as_ref() else {
            continue;
        };
        if candidate.entity_type == ENTITY_TYPE_CLAIM && is_calendar_family_row(fields) {
            continue;
        }
        let Some(text) = PREP_CONTEXT_TEXT_FIELD_ALIASES.into_iter().find_map(|key| {
            fields
                .get(key)
                .and_then(|value| first_text_leaf(value, PREP_TEXT_LEAF_MAX_DEPTH))
        }) else {
            continue;
        };
        if vault.is_deleted_shell(&candidate.id)? {
            continue;
        }
        let Some(header) = vault.read_entity_header(&candidate.id)? else {
            continue;
        };
        items.push((
            candidate.id,
            PrepItem {
                kind,
                text,
                source_refs: vec![candidate.id.to_hex()],
                observed_at: header.learned_at,
            },
        ));
    }
    Ok(items)
}

/// Whether one hydrated CLAIM row belongs to CAL-00's `calendar.*` family.
///
/// Those rows are the meeting's own scaffolding — time kind, zone, recurrence,
/// passport, origin, status, attendee lines — not evidence ABOUT the meeting,
/// and they sit one reverse hop from every EVENT seed. Ranking a `PARTSTAT`
/// token as a prior commitment would be a category error, so the family is
/// skipped here and read only where it is authoritative: `live_prep_event`,
/// for the due-time recheck.
fn is_calendar_family_row(fields: &HashMap<String, serde_json::Value>) -> bool {
    fields
        .get(PREP_CLAIM_PREDICATE_FIELD)
        .and_then(serde_json::Value::as_str)
        .is_some_and(is_calendar_claim_predicate)
}

/// The first non-blank string inside one hydrated field value.
///
/// Structured values (a claim value that is a map, say) are descended in the
/// map's own sorted key order, so the answer is the same on every replica. The
/// depth bound keeps a pathological stored body from walking the stack.
fn first_text_leaf(value: &serde_json::Value, depth: u32) -> Option<String> {
    if depth == 0 {
        return None;
    }
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        }
        serde_json::Value::Array(entries) => entries
            .iter()
            .find_map(|entry| first_text_leaf(entry, depth - 1)),
        serde_json::Value::Object(entries) => entries
            .values()
            .find_map(|entry| first_text_leaf(entry, depth - 1)),
        _ => None,
    }
}

/// Ranks, spends the word ceiling, and groups into sections.
///
/// Ranking is total — section, then recency, then id — so two replicas assemble
/// the same pack from the same rows. The ceiling is spent strictly top-down: a
/// row that only partly fits is cut to the words that remain, and once the
/// budget is gone the rest of the ranking is dropped rather than reordered.
/// `None` means nothing survived; nothing is ever padded to fill the budget.
fn assemble_prep_pack(
    event: &PrepEvent,
    fired_at: u64,
    policy: PrepPolicy,
    mut items: Vec<(EntityId, PrepItem)>,
) -> Option<PrepPack> {
    items.sort_by_key(|(id, item)| (item.kind, std::cmp::Reverse(item.observed_at), *id));

    let mut remaining = policy.max_words;
    let mut word_count = 0_usize;
    let mut kept = Vec::with_capacity(items.len());
    for (_, mut item) in items {
        if remaining == 0 {
            break;
        }
        if word_count_of(&item.text) > remaining {
            item.text = take_words(&item.text, remaining);
        }
        let words = word_count_of(&item.text);
        if words == 0 {
            continue;
        }
        remaining -= words;
        word_count += words;
        kept.push(item);
    }

    let mut sections: Vec<PrepSection> = PREP_SECTION_ORDER
        .into_iter()
        .map(|kind| PrepSection {
            kind,
            items: Vec::new(),
        })
        .collect();
    for item in kept {
        let kind = item.kind;
        if let Some(section) = sections.iter_mut().find(|section| section.kind == kind) {
            section.items.push(item);
        }
    }
    sections.retain(|section| !section.items.is_empty());

    if sections.is_empty() {
        return None;
    }
    Some(PrepPack {
        event_ref: event.event_ref.to_hex(),
        built_at: fired_at,
        sections,
        word_count,
    })
}

/// Words in one row, by the same whitespace split the ceiling is spent in.
fn word_count_of(text: &str) -> usize {
    text.split_whitespace().count()
}

/// The first `budget` words of `text`, re-joined by single spaces.
fn take_words(text: &str, budget: usize) -> String {
    let mut out = String::with_capacity(text.len());
    for word in text.split_whitespace().take(budget) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}
