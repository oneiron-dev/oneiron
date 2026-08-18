//! CAL-06 prep pack: the render-time context pack a meeting earns at T-45.
//!
//! Five laws hold this layer together, and every function below is one of them
//! made mechanical:
//!
//! * **Nothing is precomputed.** [`build_prep_pack`] assembles from live vault
//!   state at the moment the host says the wake fired. No prep artifact is
//!   stored, indexed, or reused: this module opens no write door at all, so a
//!   pack built yesterday cannot be surfaced today. Evidence that landed after
//!   the wake was planned but before it fired is in; evidence that lands after
//!   the fire instant is out, because the assembly is scoped by learned time.
//! * **Precedence is fixed, recency is not.** Prior commitments outrank recent
//!   threads, which outrank dossier delta — [`PrepSectionKind`] declares that
//!   order and derives `Ord` from it. Newer lower-ranked material never
//!   overtakes older higher-ranked material, and the word ceiling is applied
//!   after ordering so the budget spends itself top-down.
//! * **External by default.** [`prep_is_eligible`] arms on an external
//!   attendee, a campaign linkage, or a commitment linkage. Internal-only and
//!   solo events need an explicit opt-in — per event, or crate-wide by clearing
//!   [`PrepPolicy::external_only`]. An imported `VALARM` is not one of those
//!   signals and has no representation here at all, so a feed reminder can
//!   neither arm this feature nor mint one.
//! * **Silence is an answer.** `Ok(None)` from [`build_prep_pack`] means the
//!   scoped, ranked evidence came out empty. The caller renders nothing —
//!   there is no empty card and no padded card. The 250-word default is a
//!   ceiling, never a target.
//! * **The engine owns no clock.** [`plan_prep_wake`] describes an exact host
//!   wake and returns; nothing here spawns, waits, repeats, or reads a system
//!   clock, and every timestamp is a caller argument. Closed-vault delivery is
//!   a host-owned home-node job: the host proves it holds the election, then
//!   calls [`run_due_home_node_prep`]. Election and lease storage stay in the
//!   host's hands — this module neither reads nor extends them.
//!
//! ## Two bridges this layer stands on, deliberately
//!
//! * **Wake shape.** [`PrepWake`] is the engine-side image of
//!   `oneiron_vault_contract::WakeEntry` carrying `Schedule::Exact`.
//!   `crates/oneiron` does not depend on the contract crate at this commit (the
//!   path dep is ONE-1783's reserved `Cargo.toml` append), so the three fields
//!   ride this struct and map one-to-one when that dep lands — exactly as
//!   CAL-07's [`super::outcome::OutcomeCheckInWake`] already does. CAL never
//!   plans a window, so [`PREP_WAKE_SCHEDULE_KIND`] pins the `exact` arm as a
//!   value a caller can assert without the dep.
//! * **Commitment trigger.** Until CMT-3 lands there is no commitment entity to
//!   key on, so `prep_section_kind_for` maps stored entity types onto the
//!   three ranked sections. That mapping is the swap point: when CMT-3 arrives,
//!   the commitment section keys on commitment rows instead of CLAIM rows and
//!   nothing else in this module moves.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::claims::{
    CalendarStatus, PREDICATE_CALENDAR_ATTENDEE, PREDICATE_CALENDAR_STATUS, decode_attendee_value,
    decode_status_value, is_calendar_claim_predicate,
};
use crate::claim::claim_surfaceable;
use crate::context_pack::ContextEntity;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::lens::{
    GeneratedLens, GeneratedUiPrebuilt, GeneratedUiSummaryCardPrebuilt, LensText, MetaLineAtom,
};
use crate::ppr::MAX_PPR_SEEDS;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::vault::Vault;

/// Default lead between the EVENT start and the prep wake: T-45.
pub const DEFAULT_PREP_LEAD_SECS: u64 = 45 * 60;

/// Default ceiling on the assembled pack. A ceiling, not a target.
pub const DEFAULT_PREP_MAX_WORDS: usize = 250;

/// Opaque tag the host echoes back when the prep wake fires.
///
/// Seventeen bytes, so it clears the contract's 64-byte `reason_tag` bound with
/// room to spare.
pub const PREP_WAKE_REASON_TAG: &str = "calendar.prep.t45";

/// The `Schedule` arm every prep wake carries.
///
/// The contract's `Schedule` is tagged `#[serde(tag = "kind", rename_all =
/// "snake_case")]`, so `Schedule::Exact` is the wire token `exact`. CAL plans no
/// window: the fire instant is computed at schedule time and recomputed when the
/// EVENT moves, which leaves the host nothing to jitter.
pub const PREP_WAKE_SCHEDULE_KIND: &str = "exact";

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

/// Joins the source refs backing one rendered row.
const PREP_SOURCE_REF_SEPARATOR: &str = " ";

/// Joins rendered rows inside the summary card body.
const PREP_LINE_SEPARATOR: &str = "\n";

/// Machine label for the card's EVENT backing line. A token, not product copy —
/// the same stance CAL-07's check-in card takes.
const PREP_LENS_EVENT_REF_LABEL: &str = "event_ref";

/// The fixed section order. Declaration order in [`PrepSectionKind`] is the
/// precedence rule; this array is the same rule as data, so assembly walks it
/// instead of re-deriving it.
const PREP_SECTION_ORDER: [PrepSectionKind; 3] = [
    PrepSectionKind::PriorCommitment,
    PrepSectionKind::AttendeeThread,
    PrepSectionKind::DossierDelta,
];

/// Tunables for one vault's prep behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepPolicy {
    /// Seconds before the EVENT start at which the wake fires.
    pub lead_secs: u64,
    /// Ceiling on the assembled pack, counted after ordering.
    pub max_words: usize,
    /// Whether internal-only and solo events need a per-event opt-in.
    pub external_only: bool,
}

impl Default for PrepPolicy {
    fn default() -> Self {
        Self {
            lead_secs: DEFAULT_PREP_LEAD_SECS,
            max_words: DEFAULT_PREP_MAX_WORDS,
            external_only: true,
        }
    }
}

/// The EVENT facts prep eligibility and scoping are decided from.
///
/// Externality, campaign linkage, and commitment linkage are caller-supplied:
/// the engine models attendees as vendor strings on `calendar.attendee` and owns
/// no identity domain, so only the host can say which attendee is outside the
/// house. There is no `VALARM` field, by design — an imported reminder block is
/// not an eligibility signal and cannot become one by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepEvent {
    /// The EVENT this pack is about.
    pub event_ref: EntityId,
    /// Scheduled start, unix seconds UTC.
    pub start_utc: u64,
    /// Scheduled end, unix seconds UTC.
    pub end_utc: u64,
    /// Attendee entities, used as additional assembly seeds.
    pub attendee_refs: Vec<EntityId>,
    /// How many attendees are outside the owner's house.
    pub external_attendee_count: u32,
    /// Whether the EVENT is linked to a campaign.
    pub has_campaign_linkage: bool,
    /// Whether the EVENT is linked to a commitment.
    pub has_commitment_linkage: bool,
    /// Per-event opt-in that arms an internal-only or solo event.
    pub internal_meeting_opt_in: bool,
}

/// Whether this EVENT arms prep at all.
///
/// External-meetings-only is the default: one external attendee, a campaign
/// linkage, or a commitment linkage each arm on their own. An internal-only or
/// solo EVENT arms only on an explicit opt-in — per event via
/// [`PrepEvent::internal_meeting_opt_in`], or vault-wide by clearing
/// [`PrepPolicy::external_only`]. Both are opt-ins; neither is a default.
#[must_use]
pub fn prep_is_eligible(event: &PrepEvent, policy: PrepPolicy) -> bool {
    if event.external_attendee_count > 0
        || event.has_campaign_linkage
        || event.has_commitment_linkage
    {
        return true;
    }
    !policy.external_only || event.internal_meeting_opt_in
}

/// One exact host wake: the three fields of the supervisor wake contract.
///
/// The engine-side image of `oneiron_vault_contract::WakeEntry` with
/// `Schedule::Exact` — see the module note on why the contract type is not
/// named directly at this commit. `at_utc` maps to `Schedule::Exact { at }`;
/// the other two fields map by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepWake {
    /// Stable wake id. Rescheduling reuses it so the host REPLACES the entry.
    pub id: String,
    /// Exact fire instant, unix seconds UTC.
    pub at_utc: u64,
    /// Opaque tag echoed back when the wake fires.
    pub reason_tag: String,
}

/// The stable wake id for one EVENT's prep purpose.
///
/// Stability is the whole point: the host keys its wake table on this id, so
/// recomputing the wake after the EVENT moves replaces the old entry instead of
/// adding a second one. Derived from the EVENT and the purpose tag alone, so two
/// callers that never met agree on it, and it stays inside the contract's
/// 128-byte wake-id bound (17 + 1 + 32 bytes).
#[must_use]
pub fn prep_wake_id(event_ref: &EntityId) -> String {
    format!("{PREP_WAKE_REASON_TAG}:{}", event_ref.to_hex())
}

/// The exact T-45 instant for one EVENT, or `None` when it cannot be
/// represented — an EVENT starting inside the first 45 minutes of the epoch has
/// no lead time, and saturating it to zero would mint a wake in 1970.
fn prep_fire_at(event: &PrepEvent, policy: PrepPolicy) -> Option<u64> {
    event.start_utc.checked_sub(policy.lead_secs)
}

/// Plans the T-45 prep wake for one EVENT, or `None` when the EVENT is
/// ineligible or T-45 cannot be represented.
///
/// The engine owns no clock: this only describes the wake the host is asked to
/// deliver. Call it again when the EVENT is rescheduled — with the same
/// [`prep_wake_id`], so the new entry replaces the old one rather than
/// multiplying wakes.
#[must_use]
pub fn plan_prep_wake(wake_id: String, event: &PrepEvent, policy: PrepPolicy) -> Option<PrepWake> {
    if !prep_is_eligible(event, policy) {
        return None;
    }
    let fire_at = prep_fire_at(event, policy)?;
    Some(PrepWake {
        id: wake_id,
        at_utc: fire_at,
        reason_tag: PREP_WAKE_REASON_TAG.to_owned(),
    })
}

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
        let Some(text) = PREP_CONTEXT_TEXT_FIELD_ALIASES
            .into_iter()
            .find_map(|key| {
                fields
                    .get(key)
                    .and_then(|value| first_text_leaf(value, PREP_TEXT_LEAF_MAX_DEPTH))
            })
        else {
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

/// The human half of a prep card. Every string is a runtime/config input:
/// engine Rust hardcodes no product prose, persona, or localized text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepLensCopy {
    /// Card title.
    pub title: String,
    /// Heading over [`PrepSectionKind::PriorCommitment`].
    pub commitment_heading: String,
    /// Heading over [`PrepSectionKind::AttendeeThread`].
    pub thread_heading: String,
    /// Heading over [`PrepSectionKind::DossierDelta`].
    pub dossier_heading: String,
}

impl PrepLensCopy {
    /// The caller's heading for one section.
    #[must_use]
    pub fn heading_for(&self, kind: PrepSectionKind) -> &str {
        match kind {
            PrepSectionKind::PriorCommitment => self.commitment_heading.as_str(),
            PrepSectionKind::AttendeeThread => self.thread_heading.as_str(),
            PrepSectionKind::DossierDelta => self.dossier_heading.as_str(),
        }
    }
}

/// Renders one pack as a generated summary-card lens.
///
/// Composition only: the structure is the pack's, every word of chrome is the
/// caller's, and each rendered row carries its backing vault ids as a detail
/// line so nothing on the card is unattributed. There is no rendering path for
/// an absent pack — `Ok(None)` from [`build_prep_pack`] means the caller emits
/// no lens at all.
///
/// # Errors
///
/// [`crate::error::Error::InvalidConfig`] when caller-supplied copy violates the
/// lens text bounds, including an empty title.
pub fn render_prep_lens(pack: &PrepPack, copy: &PrepLensCopy) -> Result<GeneratedLens> {
    let row_count: usize = pack.sections.iter().map(|section| section.items.len()).sum();
    let mut body = String::new();
    let mut details = Vec::with_capacity(row_count + 1);
    details.push(MetaLineAtom {
        label: LensText::new(PREP_LENS_EVENT_REF_LABEL)?,
        value: LensText::new(pack.event_ref.as_str())?,
    });

    for section in &pack.sections {
        let heading = copy.heading_for(section.kind);
        push_prep_line(&mut body, heading);
        for item in &section.items {
            push_prep_line(&mut body, item.text.as_str());
            details.push(MetaLineAtom {
                label: LensText::new(heading)?,
                value: LensText::new(item.source_refs.join(PREP_SOURCE_REF_SEPARATOR))?,
            });
        }
    }

    let card = GeneratedUiPrebuilt::SummaryCard(GeneratedUiSummaryCardPrebuilt {
        title: LensText::new(copy.title.as_str())?,
        body: LensText::new(body)?,
        details,
    });
    GeneratedLens::new(card.expand()?)
}

/// Appends one non-empty line to the card body.
fn push_prep_line(body: &mut String, line: &str) {
    if line.is_empty() {
        return;
    }
    if !body.is_empty() {
        body.push_str(PREP_LINE_SEPARATOR);
    }
    body.push_str(line);
}

/// The closed-vault due payload: small, deterministic, and self-describing.
///
/// Three scalars and nothing else. The raw context stays in the vault and is
/// re-read at execution time, so this payload can sit in a host queue across a
/// vault close without ever becoming stale prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepHomeNodeJob {
    /// Hex id of the EVENT the pack is about.
    pub event_ref: String,
    /// The exact instant the wake was planned for, unix seconds UTC.
    pub scheduled_for: u64,
    /// The wake id the host will report as due.
    pub wake_id: String,
}

impl PrepHomeNodeJob {
    /// Binds one planned wake to the EVENT it was planned for.
    ///
    /// Deterministic: the same EVENT and the same wake always produce the same
    /// payload, so a host that enqueues twice enqueues the same bytes.
    #[must_use]
    pub fn from_wake(event_ref: &EntityId, wake: &PrepWake) -> Self {
        Self {
            event_ref: event_ref.to_hex(),
            scheduled_for: wake.at_utc,
            wake_id: wake.id.clone(),
        }
    }
}

/// Runs one due prep job on the elected home node.
///
/// The host calls this AFTER proving it holds the home-node election. This
/// module owns no part of that proof: it reads no lease, writes no lease, and
/// exposes no second door a due payload could enter through.
///
/// A due wake is not a card. Everything the payload asserts is re-derived from
/// the vault before anything is rendered:
///
/// * the EVENT must still exist, still be an EVENT, and not be a deleted or
///   redirect shell;
/// * it must not have been cancelled — CAL-00's `calendar.status` is the home
///   that law lives in, and a prep pack for a called-off meeting is noise;
/// * it must still be eligible, from live `calendar.attendee` rows;
/// * its T-45 must still be the instant the payload was planned for. An EVENT
///   that moved has a new wake with the same [`prep_wake_id`]; this one is
///   stale and answers `None` rather than rendering against an old time.
///
/// `Ok(None)` therefore covers both "stale" and "now empty", and in both cases
/// the caller emits no lens.
///
/// # Errors
///
/// [`crate::error::Error::InvalidKey`] when `event_ref` is not a hex entity id;
/// storage, claim-body, retrieval, and lens errors propagate unchanged.
pub fn run_due_home_node_prep(
    vault: &Vault,
    job: &PrepHomeNodeJob,
    fired_at: u64,
    policy: PrepPolicy,
    copy: &PrepLensCopy,
) -> Result<Option<GeneratedLens>> {
    let event_ref = EntityId::from_hex(&job.event_ref)?;
    let Some(event) = live_prep_event(vault, event_ref)? else {
        return Ok(None);
    };
    if prep_fire_at(&event, policy) != Some(job.scheduled_for) {
        return Ok(None);
    }
    let request = PrepBuildRequest {
        event,
        fired_at,
        policy,
    };
    let Some(pack) = build_prep_pack(vault, &request)? else {
        return Ok(None);
    };
    render_prep_lens(&pack, copy).map(Some)
}

/// Re-derives the EVENT facts this layer can read for itself at due time.
///
/// `None` means the EVENT is gone, is not an EVENT, is a shell, or has been
/// cancelled. What comes back is deliberately narrower than what a host can
/// supply: the engine models attendees as vendor strings and owns no identity
/// domain, so every live `calendar.attendee` row counts once and campaign,
/// commitment, and opt-in signals stay false. That makes the due-time recheck a
/// NARROWING one — it can retire a job the host already armed, never arm one the
/// host did not. A host with an identity model gets a sharper answer by calling
/// [`build_prep_pack`] with its own [`PrepEvent`].
fn live_prep_event(vault: &Vault, event_ref: EntityId) -> Result<Option<PrepEvent>> {
    let Some(header) = vault.read_entity_header(&event_ref)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.is_deleted_shell(&event_ref)? {
        return Ok(None);
    }
    let facts = live_event_facts(vault, &event_ref)?;
    if facts.cancelled {
        return Ok(None);
    }
    let (start_utc, end_utc) = if header.occurred_start <= header.occurred_end {
        (header.occurred_start, header.occurred_end)
    } else {
        (header.occurred_end, header.occurred_start)
    };
    Ok(Some(PrepEvent {
        event_ref,
        start_utc,
        end_utc,
        attendee_refs: Vec::new(),
        external_attendee_count: facts.attendee_count,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }))
}

/// The two live calendar facts the due-time recheck reads.
struct LiveEventFacts {
    cancelled: bool,
    attendee_count: u32,
}

/// Reads live `calendar.attendee` and `calendar.status` heads on one EVENT.
///
/// Surfaceable heads only, through the ordinary claim door — a gate-pending row
/// is not a fact a card may be built on. Both predicates belong to CAL-00; this
/// layer reads them and writes neither.
fn live_event_facts(vault: &Vault, event_ref: &EntityId) -> Result<LiveEventFacts> {
    let rtxn = vault.store.env.read_txn()?;
    let mut cancelled = false;
    let mut attendee_count = 0_u32;
    for claim_id in vault.claims_for_subject_in_txn(&rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(&rtxn, &claim_id)?
            .filter(claim_surfaceable)
        else {
            continue;
        };
        if body.predicate == PREDICATE_CALENDAR_ATTENDEE {
            // Decoded, not just counted: a row that is not a well-formed
            // attendee line is a claim-body error, never a silent head count.
            decode_attendee_value(&body.value)?;
            attendee_count = attendee_count.saturating_add(1);
        } else if body.predicate == PREDICATE_CALENDAR_STATUS
            && decode_status_value(&body.value)?.status == CalendarStatus::Cancelled
        {
            cancelled = true;
        }
    }
    Ok(LiveEventFacts {
        cancelled,
        attendee_count,
    })
}
