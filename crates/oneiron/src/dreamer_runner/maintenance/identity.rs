//! Background identity checks (OF-123; owner ruling: ask rule B).
//!
//! In conversation the tagger links cheaply and cautiously: every identity
//! key hit is a soft `Candidates` link and a miss mints a local provisional
//! entity, so a person never waits on a match. This module checks those
//! links again later. Each night [`IDENTITY_RECHECK_FACET`] walks a page of
//! saved tag sets. A mention of a person that names two or more entities, or
//! a provisional one whose name now keys to a real person, is uncertain. A
//! saved context hint settles it when the words around it match the words an
//! earlier answer was given in. Each other one opens an identity ask, one
//! open ask per name and candidate set.
//!
//! The host asks each open ask as one decide() Choice over the candidates
//! plus [`SOMEONE_NEW`] ([`Vault::decide_identity_ask`]). A choice settles
//! the mention. An abstention on a nightly ask keeps the names separate for
//! now (OF-023): nothing merges, nothing is confirmed and no one is asked.
//! The ask stays open and answerable, is not decided again until its
//! candidates change, and leaves the Dreamer's receipt, which the owner
//! reverts into today's question to them. An abstention on an act-now ask
//! goes to the person: one inbox Ask NOTIFICATION per owner in the
//! conversation the name came from (the needs-you strip), sent again in the
//! conversation that next mentions the name
//! ([`Vault::resurface_identity_asks`]), with a one-tap GenUI choice card
//! ([`Vault::identity_card`]) whose buttons answer through
//! `self.identity.answer`.
//!
//! An agent that must act on a person now (send, pay, invite, share) asks
//! first through `self.identity.settle` ([`Memory::identity_act_now`]): a
//! settled name answers at once, and an uncertain one opens an act-now ask
//! the host decides before any other.
//!
//! Every answer saves the resolution and a context hint (the name, the words
//! around it and the entity it named), so the same question rarely returns.
//! Someone new confirms the mention's provisional entity as a real, synced
//! person and asserts it distinct from each real candidate (ARCH-0055 §6), so
//! no merge of the two is proposed again.
use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::MAINTENANCE_QUEUE_KIND;
use super::applied::{MaintenanceInverse, MaintenanceRevert, MaintenanceTarget};
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::identity_topology::{AssertDistinctOp, IdentityOpWrite, IdentityTopologyOp};
use crate::lens::{
    ButtonControl, GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier,
    GeneratedUiCard, GeneratedUiStateSnapshot, LensAtom, LensAtomId, LensNode, LensRenderId,
    LensText, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiValue,
    VoiceLineAtom,
};
use crate::llm::decision::catalogue::IDENTITY_SETTLE;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    MAX_DECISION_STATE_BYTES, Reversibility,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
use crate::tagging::MentionLink;
use crate::{EntityId, Error, Result, Vault};

pub const IDENTITY_RECHECK_FACET: &str = "dreamer.identity_recheck";
/// The producer of an identity ask's inbox NOTIFICATION; `source.result`
/// names the ask.
pub const IDENTITY_NOTIFICATION_PRODUCER: &str = "dreamer.identity";
/// The Choice option for "someone new": none of the candidates.
pub const SOMEONE_NEW: &str = "someone_new";
/// The verb a choice card's buttons answer through.
pub const IDENTITY_ANSWER_VERB: &str = "self.identity.answer";
/// A candidate's option: this prefix, then its id.
const IS_PREFIX: &str = "is:";
/// Tag sets one nightly pass reads.
const SCAN_TURNS: usize = 2_048;
/// Open asks at once, besides those kept separate: past this a pass opens
/// none.
const MAX_OPEN_ASKS: usize = 64;
/// Candidates one Choice carries beside "someone new".
const MAX_CANDIDATES: usize = 63;
/// Context words one mention keeps.
const MAX_TERMS: usize = 16;
/// Context words one hint keeps.
const MAX_HINT_TERMS: usize = 64;
const MIN_TERM_CHARS: usize = 4;
/// Bytes of text around a mention its ask keeps for the decision.
const EXCERPT_BYTES: usize = 480;
const MAX_NAME_BYTES: usize = 256;
/// How long a failed decision waits before the host tries again.
const RETRY_SECS: u64 = 3_600;
/// The rationale on a someone-new answer's `assert_distinct` event.
const SOMEONE_NEW_RATIONALE: &str = "identity ask: someone new";
/// Words too common to tell two people apart.
const STOP_WORDS: &[&str] = &[
    "about", "after", "again", "also", "been", "before", "being", "could", "does", "doing", "done",
    "from", "going", "have", "here", "just", "know", "like", "made", "make", "many", "more",
    "much", "only", "over", "really", "said", "says", "should", "some", "still", "than", "that",
    "their", "them", "then", "there", "these", "they", "thing", "think", "this", "those", "very",
    "want", "were", "what", "when", "where", "which", "while", "will", "with", "would", "yeah",
    "your",
];

/// Open asks. Key: [`ask_key`] of the mention.
const ASKS: SideTable<[u8; 32], IdentityAsk, Named> =
    SideTable::new(&side_table::DREAMER_IDENTITY_ASK);
/// The last turn the nightly pass read.
const CURSOR: SideTable<(), EntityId, Named> = SideTable::new(&side_table::DREAMER_IDENTITY_CURSOR);
/// Context hints. Key: kind, the name's identity-hint digest, the entity.
const HINTS: SideTable<([u8; 1], [u8; 32], EntityId), IdentityHint, Named> =
    SideTable::new(&side_table::DREAMER_IDENTITY_HINT);

/// What an agent must do to the person now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEffect {
    Send,
    Pay,
    Invite,
    Share,
}

/// Why an ask is open (ask rule B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAskReason {
    /// An agent must act on this person now.
    ActNow { effect: IdentityEffect },
    /// The Dreamer's pass could not settle it.
    Unsettled,
}

/// One saved mention whose person is not settled, and where its ask stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAsk {
    pub kind: u8,
    /// The span's text.
    pub name: String,
    pub turn: EntityId,
    pub message: EntityId,
    pub start: usize,
    pub end: usize,
    /// The entities it may be, real or provisional.
    pub candidates: Vec<EntityId>,
    /// The mention's own provisional entity, when it named only that one and
    /// the name now keys to real people: "someone new" confirms it.
    pub provisional: Option<EntityId>,
    /// The words around the mention, as a hint keeps them.
    pub context: Vec<String>,
    /// The text around the mention, for the decision.
    pub excerpt: String,
    pub reason: IdentityAskReason,
    pub opened_at: u64,
    /// No decision before this; 0 asks at once.
    pub retry_at: u64,
    /// When the decision abstained and the ask went to the person.
    pub escalated_at: Option<u64>,
    /// The newest turn the ask was sent to the person from.
    pub surfaced_turn: Option<EntityId>,
    /// When a nightly decision abstained and the names were kept separate
    /// for now: the ask is not due until its candidates change.
    pub kept_separate_at: Option<u64>,
}

/// The words an answer about a name was given in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityHint {
    pub name: String,
    pub context: Vec<String>,
    pub saved_at: u64,
}

/// One option of an ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityOption {
    /// The Choice token: `is:<id>`, or [`SOMEONE_NEW`].
    pub choice: String,
    /// The candidate, as 32 hex; none for someone new.
    pub entity: Option<String>,
    /// Its stored name; empty for someone new.
    pub label: String,
    pub provisional: bool,
    /// When a provisional candidate was first said, store-clock seconds.
    pub first_said: Option<u64>,
}

/// An open ask as the owner reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAskView {
    /// The ask, as 64 hex.
    pub ask: String,
    pub name: String,
    pub turn: String,
    pub conversation: Option<String>,
    pub excerpt: String,
    pub options: Vec<IdentityOption>,
    pub reason: IdentityAskReason,
    pub opened_at: u64,
    pub escalated_at: Option<u64>,
    /// When the names were kept separate for now; the ask still takes an
    /// answer.
    pub kept_separate_at: Option<u64>,
}

/// The words a choice card shows, in the person's language: the host's or
/// the asking agent's, never the engine's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCardCopy {
    pub prompt: String,
    pub someone_new: String,
    /// A provisional candidate's button: `{name}` takes its name and `{day}`
    /// the day it was first said. None shows `{name} · {day}`.
    pub provisional: Option<String>,
}

/// The host's decision path for an ask: its ladder, the principal the
/// answer is for, the dial and bands, its wording of the question, and the
/// call's clock.
pub struct IdentityDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub deadline: &'a RetrievalDeadline,
}

/// What one decision did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRuling {
    /// The mention names this entity now.
    Settled(EntityId),
    /// The ladder abstained on an act-now ask: the ask went to the person.
    NeedsPerson,
    /// The ladder abstained on a nightly ask: the names stay separate for
    /// now, and the ask waits, answerable, for its candidates to change.
    KeptSeparate,
    /// The ladder failed: the ask waits and is decided again.
    Retry,
    /// The ask was answered or changed meanwhile.
    Gone,
}

/// A settled ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentitySettled {
    pub ask: String,
    /// The entity the mention names, as 32 hex.
    pub entity: String,
}

/// `self.identity.answer`'s input: the person's choice on one ask.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAnswerRequest {
    /// The ask, as 64 hex.
    pub ask: String,
    /// One of the ask's options: `is:<id>` or `someone_new`.
    pub choice: String,
}

/// `self.identity.settle`'s input: an agent about to act on a person it
/// knows by the name a conversation used.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityActNowRequest {
    /// The name as the conversation said it.
    pub name: String,
    /// The conversation it was said in, as 32 hex; any when absent.
    #[serde(default)]
    pub conversation: Option<String>,
    pub effect: IdentityEffect,
    /// The choice card's question, in the person's language.
    pub prompt: String,
    /// The choice card's label for someone new, in the person's language.
    pub someone_new: String,
}

/// Where a name an agent must act on stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IdentityActNow {
    /// The name settles to this entity: act on it.
    Settled { entity: String },
    /// No saved mention names it: there is nothing to settle against.
    Unknown,
    /// The host is deciding: ask again shortly, and do not act yet.
    Deciding { ask: String },
    /// The person must choose: show the card, and act only on their answer.
    NeedsPerson {
        ask: String,
        card: serde_json::Value,
    },
}

/// The person a choice names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Is(EntityId),
    SomeoneNew,
}

/// Where an effect's person target came from: one saved mention (OF-123
/// act-now guard). An effect door that carries it refuses while the mention
/// is unsettled ([`mention_unsettled_in_txn`]), and the agent settles it
/// through `self.identity.settle` first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MentionProvenance {
    /// The turn whose tags hold the mention, as 32 hex.
    pub turn: String,
    /// The message the mention is in, as 32 hex.
    pub message: String,
    /// The mention's byte span in the message text.
    pub start: u64,
    pub end: u64,
}

/// The name of a mention an effect may not act on yet: its ask is open, or
/// it is still uncertain and no saved hint settles it. Provenance that names
/// no saved mention is unsettled too, with an empty name. Reads only, in the
/// caller's snapshot: no ask opens here.
pub(crate) fn mention_unsettled_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mention: &MentionProvenance,
) -> Result<Option<String>> {
    let (Ok(turn), Ok(message), Ok(start), Ok(end)) = (
        EntityId::from_hex(&mention.turn),
        EntityId::from_hex(&mention.message),
        usize::try_from(mention.start),
        usize::try_from(mention.end),
    ) else {
        return Ok(Some(String::new()));
    };
    let current = crate::tagging::tag_set_in_txn(&vault.store, txn, &turn)?.and_then(|tags| {
        tags.mentions
            .into_iter()
            .find(|each| each.message == message && each.start == start && each.end == end)
    });
    let Some(current) = current else {
        return Ok(Some(String::new()));
    };
    let Some(text) = crate::tagging::message_text_in_txn(vault, txn, &turn, &message)? else {
        return Ok(Some(String::new()));
    };
    let name = text
        .get(start..end)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if ASKS.contains(&vault.store, txn, &ask_key(&turn, &message, start, end))? {
        return Ok(Some(name));
    }
    let Some(ask) = ask_for_mention_in_txn(
        vault,
        txn,
        &turn,
        &current,
        &text,
        IdentityAskReason::Unsettled,
        0,
    )?
    else {
        return Ok(None);
    };
    if hinted_in_txn(vault, txn, &ask)?.is_some() {
        return Ok(None);
    }
    Ok(Some(name))
}

/// An uncertain mention, before it is an ask.
struct Uncertain {
    kind: u8,
    candidates: Vec<EntityId>,
    provisional: Option<EntityId>,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("identity ask: {message}"))
}

/// The key of the ask for the span of `turn` at `message`, `start`..`end`.
fn ask_key(turn: &EntityId, message: &EntityId, start: usize, end: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.identity_ask.v1");
    hasher.update(turn.as_bytes());
    hasher.update(message.as_bytes());
    hasher.update(&u64::try_from(start).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(&u64::try_from(end).unwrap_or(u64::MAX).to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn key_hex(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut key = [0_u8; 32];
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| word.chars().count() >= MIN_TERM_CHARS)
        .map(str::to_lowercase)
        .filter(|word| !STOP_WORDS.contains(&word.as_str()))
}

/// The words nearest a span, outward from it, once each, without the name's
/// own words.
fn context_terms(text: &str, start: usize, end: usize, name: &str) -> Vec<String> {
    let own: BTreeSet<String> = words(name).collect();
    let mut before: Vec<String> = words(text.get(..start).unwrap_or("")).collect();
    before.reverse();
    let after: Vec<String> = words(text.get(end..).unwrap_or("")).collect();
    let mut seen = BTreeSet::new();
    let mut terms = Vec::new();
    for index in 0..before.len().max(after.len()) {
        for word in [before.get(index), after.get(index)].into_iter().flatten() {
            if terms.len() < MAX_TERMS && !own.contains(word) && seen.insert(word.clone()) {
                terms.push(word.clone());
            }
        }
    }
    terms
}

/// The text around a span, cut on character boundaries.
fn excerpt(text: &str, start: usize, end: usize) -> String {
    let half = EXCERPT_BYTES / 2;
    let mut from = start.saturating_sub(half).min(text.len());
    while from > 0 && !text.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = end.saturating_add(half).min(text.len());
    while to < text.len() && !text.is_char_boundary(to) {
        to += 1;
    }
    text.get(from..to).unwrap_or_default().to_owned()
}

/// Whether `id` is a stored entity of `kind`.
fn entity_of_kind_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> Result<bool> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .is_some_and(|raw| raw.first() == Some(&kind)),
    )
}

/// A candidate's name: a provisional entity's own, a stored person's
/// display name or name, else the short id.
fn label_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<String> {
    if let Some(entity) = crate::tagging::provisional_in_txn(&vault.store, txn, id)? {
        return Ok(entity.name);
    }
    let name =
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?.and_then(|raw| {
            if crate::batch::EntityMetadataHeader::parse(&raw).is_none()
                || raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                return None;
            }
            let mut body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
            let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut body) else {
                return None;
            };
            ["display_name", "name"].iter().find_map(|wanted| {
                entries.iter().find_map(|(key, value)| {
                    (key.as_str() == Some(*wanted))
                        .then(|| value.as_str())
                        .flatten()
                        .filter(|text| !text.trim().is_empty())
                        .map(str::to_owned)
                })
            })
        });
    Ok(name.unwrap_or_else(|| id.to_hex().chars().take(8).collect()))
}

/// Whether the link in `turn` is an uncertain person: two or more
/// candidates, or the mention's own provisional entity alone while its name
/// keys to real people now in a world the turn is in, as the Linker filters
/// them.
fn uncertain_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    link: &MentionLink,
    name: &str,
) -> Result<Option<Uncertain>> {
    let (kind, entities) = match link {
        MentionLink::Candidates { kind, entities } => (*kind, entities.clone()),
        MentionLink::Minted { kind, entity } => (*kind, vec![*entity]),
        MentionLink::Tag => return Ok(None),
    };
    if kind != ENTITY_TYPE_PERSON || entities.is_empty() {
        return Ok(None);
    }
    if entities.len() >= 2 {
        let mut candidates = entities;
        candidates.truncate(MAX_CANDIDATES);
        return Ok(Some(Uncertain {
            kind,
            candidates,
            provisional: None,
        }));
    }
    let own = entities[0];
    if crate::tagging::provisional_in_txn(&vault.store, txn, &own)?.is_none() {
        return Ok(None);
    }
    let mut real = BTreeSet::new();
    for hit in vault.lookup_identity_key_in_txn(txn, kind, name)? {
        for head in vault.resolve_entity_in_txn(txn, &hit)? {
            if head != own
                && entity_of_kind_in_txn(vault, txn, &head, kind)?
                && crate::tagging::shares_world_in_txn(vault, txn, turn, &head)?
            {
                real.insert(head);
            }
        }
    }
    if real.is_empty() {
        return Ok(None);
    }
    let mut candidates: Vec<EntityId> = real.into_iter().take(MAX_CANDIDATES - 1).collect();
    candidates.push(own);
    Ok(Some(Uncertain {
        kind,
        candidates,
        provisional: Some(own),
    }))
}

fn hint_prefix(kind: u8, name: &str) -> Vec<u8> {
    let mut prefix = vec![kind];
    prefix.extend_from_slice(&crate::ingest::identity_hint_digest(name));
    prefix
}

/// The hints saved for a name, by the entity each named.
fn hints_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    name: &str,
) -> Result<BTreeMap<EntityId, IdentityHint>> {
    Ok(HINTS
        .scan_from(&vault.store, txn, &hint_prefix(kind, name))?
        .into_iter()
        .map(|((_, _, entity), hint)| (entity, hint))
        .collect())
}

/// The one candidate whose hint shares the most words with `terms`; none on
/// no shared word or a tie.
fn hinted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<Option<EntityId>> {
    let mut best: Option<(EntityId, usize)> = None;
    let mut tied = false;
    for (entity, hint) in hints_in_txn(vault, txn, ask.kind, &ask.name)? {
        if !ask.candidates.contains(&entity) {
            continue;
        }
        let shared = hint
            .context
            .iter()
            .filter(|term| ask.context.contains(term))
            .count();
        if shared == 0 {
            continue;
        }
        match best {
            Some((_, top)) if shared < top => {}
            Some((_, top)) if shared == top => tied = true,
            _ => {
                best = Some((entity, shared));
                tied = false;
            }
        }
    }
    Ok(best.filter(|_| !tied).map(|(entity, _)| entity))
}

/// The one of `candidates` a saved hint picks for a mention of `name` at
/// `start..end` of `text`, as the nightly re-check settles an ask: the
/// candidate whose hint shares the most words with the mention's context;
/// none on no shared word or a tie. The Linker reads it when it saves a
/// turn, so a saved hint settles a mention live.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hinted_mention_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    name: &str,
    text: &str,
    start: usize,
    end: usize,
    candidates: &[EntityId],
) -> Result<Option<EntityId>> {
    let context = context_terms(text, start, end, name);
    let mut best: Option<(EntityId, usize)> = None;
    let mut tied = false;
    for (entity, hint) in hints_in_txn(vault, txn, kind, name)? {
        if !candidates.contains(&entity) {
            continue;
        }
        let shared = hint
            .context
            .iter()
            .filter(|term| context.contains(term))
            .count();
        if shared == 0 {
            continue;
        }
        match best {
            Some((_, top)) if shared < top => {}
            Some((_, top)) if shared == top => tied = true,
            _ => {
                best = Some((entity, shared));
                tied = false;
            }
        }
    }
    Ok(best.filter(|_| !tied).map(|(entity, _)| entity))
}

/// Saves the words an answer was given in for its name and entity.
fn put_hint_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    entity: EntityId,
    now: u64,
) -> Result<()> {
    let key = (
        [ask.kind],
        crate::ingest::identity_hint_digest(&ask.name),
        entity,
    );
    let mut hint = HINTS
        .get(&vault.store, txn, &key)?
        .unwrap_or_else(|| IdentityHint {
            name: ask.name.clone(),
            context: Vec::new(),
            saved_at: now,
        });
    for term in &ask.context {
        if hint.context.len() >= MAX_HINT_TERMS {
            break;
        }
        if !hint.context.contains(term) {
            hint.context.push(term.clone());
        }
    }
    hint.saved_at = now;
    HINTS.put(&vault.store, txn, &key, &hint)
}

/// The person an option names, when it is one of the ask's.
fn parse_choice(ask: &IdentityAsk, choice: &str) -> Option<Answer> {
    if choice == SOMEONE_NEW {
        return Some(Answer::SomeoneNew);
    }
    let hex = choice.strip_prefix(IS_PREFIX)?;
    ask.candidates
        .iter()
        .find(|id| id.to_hex() == hex)
        .map(|id| Answer::Is(*id))
}

/// Asserts the new person `fresh` distinct from each real person the ask
/// offered, as each resolves now (ARCH-0055 §6: "different things" mints
/// `assert_distinct`), with `source` as the claim's. Nothing when `fresh` is
/// no stored entity: no readable text named it any more.
fn assert_distinct_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    fresh: EntityId,
    source: ClaimSource,
    now: u64,
) -> Result<()> {
    if !entity_of_kind_in_txn(vault, txn, &fresh, ask.kind)? {
        return Ok(());
    }
    let mut real = BTreeSet::new();
    for candidate in &ask.candidates {
        for head in vault.resolve_entity_in_txn(txn, candidate)? {
            if head != fresh
                && entity_of_kind_in_txn(vault, txn, &head, ask.kind)?
                && crate::deletion::topology_delete_reservation_in_txn(&vault.store, txn, &head)?
                    .is_none()
            {
                real.insert(head);
            }
        }
    }
    let write = IdentityOpWrite::auto(source);
    for head in real {
        vault.apply_identity_topology_op_in_txn(
            txn,
            &IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
                a: fresh,
                b: head,
                reason: SOMEONE_NEW_RATIONALE.to_owned(),
            }),
            &write,
            now,
        )?;
    }
    Ok(())
}

/// Settles the ask's mention as `answer` and saves the hint: a chosen
/// candidate takes the span (and absorbs the mention's own provisional
/// entity, everywhere it is named); someone new keeps that provisional
/// entity, or mints one for the span, confirms it as a real person and
/// asserts it distinct from the real candidates, said by `source`.
fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    answer: Answer,
    source: ClaimSource,
    now: u64,
) -> Result<EntityId> {
    let span = (&ask.message, ask.start, ask.end);
    let entity = match answer {
        Answer::Is(chosen) => {
            let absorbed = match ask.provisional {
                Some(own) if own != chosen => {
                    crate::tagging::resolve_provisional_in_txn(vault, txn, &own, &chosen)?
                }
                _ => false,
            };
            if !absorbed {
                crate::tagging::settle_mention_in_txn(vault, txn, &ask.turn, span, chosen)?;
            }
            chosen
        }
        Answer::SomeoneNew => {
            let fresh = match ask.provisional {
                Some(own) => own,
                None => crate::tagging::mint_for_span_in_txn(
                    vault, txn, ask.kind, &ask.name, ask.turn, now,
                )?,
            };
            crate::tagging::settle_mention_in_txn(vault, txn, &ask.turn, span, fresh)?;
            crate::tagging::confirm_provisional_in_txn(vault, txn, &fresh)?;
            assert_distinct_in_txn(vault, txn, ask, fresh, source, now)?;
            fresh
        }
    };
    put_hint_in_txn(vault, txn, ask, entity, now)?;
    Ok(entity)
}

/// Settles an open ask and closes it.
fn settle_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    ask: &IdentityAsk,
    answer: Answer,
    source: ClaimSource,
    now: u64,
) -> Result<EntityId> {
    let entity = apply_in_txn(vault, txn, ask, answer, source, now)?;
    ASKS.delete(&vault.store, txn, key)?;
    Ok(entity)
}

/// One inbox Ask per owner, in the conversation of `turn`: a new row per
/// ask and turn, so a later mention surfaces it again.
fn notify_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    turn: &EntityId,
    now: u64,
) -> Result<()> {
    let conversation = crate::conversation_dag::conversation_of(&vault.store, txn, turn).ok();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let ask = key_hex(key);
    for owner in owners {
        vault.record_notification_in_txn(
            txn,
            &crate::inbox::NotificationEvent {
                kind: crate::inbox::NotificationKind::Ask,
                source: crate::inbox::NotificationSource {
                    producer: IDENTITY_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{ask}:{}:{}", turn.to_hex(), owner.to_hex()),
                    result: Some(ask.clone()),
                    ..crate::inbox::NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(owner),
                created_at: now,
                origin_conversation: conversation,
            },
        )?;
    }
    Ok(())
}

/// A nightly abstention's inverse: the ask as it stood before the names were
/// kept separate, and when they were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionalInverse {
    prior: IdentityAsk,
    kept_at: u64,
}

/// Keeps the names separate for now (OF-023): a nightly decision that
/// abstained merges, confirms and asks nothing. The candidates and the
/// mention's provisional entity stay as they are; the ask stays open and
/// answerable, out of the due list until its candidates change. The
/// Dreamer's receipt and the prior ask let the owner revert it.
fn keep_separate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    ask: IdentityAsk,
    now: u64,
) -> Result<()> {
    let kept = IdentityAsk {
        kept_separate_at: Some(now),
        ..ask.clone()
    };
    ASKS.put(&vault.store, txn, key, &kept)?;
    let actor = vault.dreamer_authority_in_txn(txn, now)?;
    super::applied::record_disposition_in_txn(
        vault,
        txn,
        *key,
        IDENTITY_RECHECK_FACET,
        actor,
        MaintenanceInverse::IdentityProvisional(Box::new(ProvisionalInverse {
            prior: ask,
            kept_at: now,
        })),
        now,
    )
}

/// The owner's revert of a kept-separate ask: the ask as it stood before
/// goes to them as today's question, an inbox Ask with its choice card, as
/// reverting "keep them separate for now" means "ask me". An ask answered,
/// decided again or taken up for an act-now effect since is left alone.
pub(super) fn revert_provisional_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    inverse: &ProvisionalInverse,
    now: u64,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    let MaintenanceTarget::IdentityAsk(key) = out.target else {
        return Err(invalid("the revert names no ask"));
    };
    let kept = IdentityAsk {
        kept_separate_at: Some(inverse.kept_at),
        ..inverse.prior.clone()
    };
    if ASKS.get(&vault.store, txn, &key)?.as_ref() != Some(&kept) {
        out.left_alone.push(key_hex(&key));
        return Ok(());
    }
    escalate_in_txn(vault, txn, &key, inverse.prior.clone(), now)?;
    out.asked.push(key_hex(&key));
    Ok(())
}

/// Sends an ask to the person: it waits on their answer from now on.
fn escalate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    mut ask: IdentityAsk,
    now: u64,
) -> Result<()> {
    ask.escalated_at = Some(now);
    ask.surfaced_turn = Some(ask.turn);
    ASKS.put(&vault.store, txn, key, &ask)?;
    notify_in_txn(vault, txn, key, &ask.turn, now)
}

/// The ask's options: each candidate, then someone new.
fn options_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<Vec<IdentityOption>> {
    let mut options = Vec::with_capacity(ask.candidates.len() + 1);
    for id in &ask.candidates {
        let first_said = crate::tagging::provisional_in_txn(&vault.store, txn, id)?
            .map(|entity| entity.minted_at);
        options.push(IdentityOption {
            choice: format!("{IS_PREFIX}{}", id.to_hex()),
            entity: Some(id.to_hex()),
            label: label_in_txn(vault, txn, id)?,
            provisional: first_said.is_some(),
            first_said,
        });
    }
    options.push(IdentityOption {
        choice: SOMEONE_NEW.to_owned(),
        entity: None,
        label: String::new(),
        provisional: false,
        first_said: None,
    });
    Ok(options)
}

fn view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    ask: &IdentityAsk,
) -> Result<IdentityAskView> {
    Ok(IdentityAskView {
        ask: key_hex(key),
        name: ask.name.clone(),
        turn: ask.turn.to_hex(),
        conversation: crate::conversation_dag::conversation_of(&vault.store, txn, &ask.turn)
            .ok()
            .map(|id| id.to_hex()),
        excerpt: ask.excerpt.clone(),
        options: options_in_txn(vault, txn, ask)?,
        reason: ask.reason,
        opened_at: ask.opened_at,
        escalated_at: ask.escalated_at,
        kept_separate_at: ask.kept_separate_at,
    })
}

/// A provisional candidate's button label: its name and the day it was first
/// said, in the copy's words when the host gave them, so it reads apart from
/// a real person of the same name.
fn provisional_label(name: &str, first_said: u64, copy: &IdentityCardCopy) -> String {
    let Some(day) = i64::try_from(first_said)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map(|at| at.format("%Y-%m-%d").to_string())
    else {
        return name.to_owned();
    };
    match &copy.provisional {
        Some(words) => words.replace("{name}", name).replace("{day}", &day),
        None => format!("{name} · {day}"),
    }
}

/// A one-tap choice card for an ask: the name and the question, then one
/// button per option. Each button answers through [`IDENTITY_ANSWER_VERB`]
/// with the ask and its option, so a click runs as the clicking person.
fn card(
    key: &[u8; 32],
    ask: &IdentityAsk,
    options: &[IdentityOption],
    copy: &IdentityCardCopy,
) -> Result<GeneratedUiCard> {
    let ask_hex = key_hex(key);
    let mut root = LensNode::new(
        LensAtomId::new("identity-voice")?,
        LensAtom::VoiceLine(VoiceLineAtom {
            speaker: LensText::new(ask.name.clone())?,
            text: LensText::new(copy.prompt.clone())?,
            vad: None,
        }),
    );
    let mut actions = Vec::with_capacity(options.len());
    for (index, option) in options.iter().enumerate() {
        let element = LensAtomId::new(format!("identity-option-{index}"))?;
        let args = json!({ "ask": ask_hex, "choice": option.choice }).to_string();
        let action = SelfUiAction {
            command: SelfUiActionId::new(IDENTITY_ANSWER_VERB)?,
            args: vec![SelfUiValue::Text(LensText::new(args)?)],
        };
        let label = match (&option.entity, option.first_said) {
            (None, _) => copy.someone_new.clone(),
            (Some(_), Some(first_said)) => provisional_label(&option.label, first_said, copy),
            (Some(_), None) => option.label.clone(),
        };
        root.children.push(LensNode::new(
            element.clone(),
            LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
                id: SelfUiControlId::new(format!("identity-option-{index}"))?,
                label: LensText::new(label)?,
                action: action.clone(),
            })),
        ));
        actions.push(GeneratedUiActionDeclaration {
            element_id: element,
            action_id: SelfUiActionId::new(format!("{IDENTITY_ANSWER_VERB}.{index}"))?,
            // The arguments are engine-authored and a click carries no
            // client state; the verb checks the ask and the answerer.
            tier: GeneratedUiActionTier::DeterministicTool,
            action,
        });
    }
    GeneratedUiCard::interactive(
        LensRenderId::new(format!("identity-{ask_hex}"))?,
        GeneratedLens::new(root)?,
        actions,
        GeneratedUiStateSnapshot::default(),
    )
}

/// Whether two asks put one question: one name, one candidate set.
fn same_question(left: &IdentityAsk, right: &IdentityAsk) -> bool {
    let set = |ask: &IdentityAsk| ask.candidates.iter().copied().collect::<BTreeSet<_>>();
    left.kind == right.kind
        && crate::ingest::identity_hint_digest(&left.name)
            == crate::ingest::identity_hint_digest(&right.name)
        && set(left) == set(right)
}

/// The ask a saved mention would open, when it is uncertain.
fn ask_for_mention_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    mention: &crate::tagging::TaggedMention,
    text: &str,
    reason: IdentityAskReason,
    now: u64,
) -> Result<Option<IdentityAsk>> {
    let Some(name) = text
        .get(mention.start..mention.end)
        .map(str::trim)
        .filter(|name| !name.is_empty() && name.len() <= MAX_NAME_BYTES)
    else {
        return Ok(None);
    };
    let Some(found) = uncertain_in_txn(vault, txn, *turn, &mention.link, name)? else {
        return Ok(None);
    };
    Ok(Some(IdentityAsk {
        kind: found.kind,
        name: name.to_owned(),
        turn: *turn,
        message: mention.message,
        start: mention.start,
        end: mention.end,
        candidates: found.candidates,
        provisional: found.provisional,
        context: context_terms(text, mention.start, mention.end, name),
        excerpt: excerpt(text, mention.start, mention.end),
        reason,
        opened_at: now,
        retry_at: 0,
        escalated_at: None,
        surfaced_turn: None,
        kept_separate_at: None,
    }))
}

/// Checks each mention of one turn again: a hint settles it, else it opens
/// an ask unless one is open for it or for its question. A kept-separate
/// ask whose candidates changed opens afresh, to be decided again.
fn recheck_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    open: &mut Vec<([u8; 32], IdentityAsk)>,
    now: u64,
) -> Result<()> {
    let Some(tags) = crate::tagging::tag_set_in_txn(&vault.store, txn, turn)? else {
        return Ok(());
    };
    let mut texts: BTreeMap<EntityId, Option<String>> = BTreeMap::new();
    for mention in &tags.mentions {
        if !texts.contains_key(&mention.message) {
            let text = crate::tagging::message_text_in_txn(vault, txn, turn, &mention.message)?;
            texts.insert(mention.message, text);
        }
        let Some(Some(text)) = texts.get(&mention.message) else {
            continue;
        };
        let key = ask_key(turn, &mention.message, mention.start, mention.end);
        if let Some((_, held)) = open.iter_mut().find(|(held, _)| *held == key) {
            if held.kept_separate_at.is_some()
                && let Some(fresh) = ask_for_mention_in_txn(
                    vault,
                    txn,
                    turn,
                    mention,
                    text,
                    IdentityAskReason::Unsettled,
                    now,
                )?
                && fresh.candidates != held.candidates
            {
                ASKS.put(&vault.store, txn, &key, &fresh)?;
                *held = fresh;
            }
            continue;
        }
        let Some(ask) = ask_for_mention_in_txn(
            vault,
            txn,
            turn,
            mention,
            text,
            IdentityAskReason::Unsettled,
            now,
        )?
        else {
            continue;
        };
        if let Some(entity) = hinted_in_txn(vault, txn, &ask)? {
            apply_in_txn(
                vault,
                txn,
                &ask,
                Answer::Is(entity),
                ClaimSource::Inferred,
                now,
            )?;
            continue;
        }
        let waiting = open
            .iter()
            .filter(|(_, held)| held.kept_separate_at.is_none())
            .count();
        if waiting >= MAX_OPEN_ASKS || open.iter().any(|(_, held)| same_question(held, &ask)) {
            continue;
        }
        ASKS.put(&vault.store, txn, &key, &ask)?;
        open.push((key, ask));
    }
    Ok(())
}

impl DreamerRunnerStore<'_> {
    /// The nightly identity re-check, one per wake key, while the vault
    /// tags its turns.
    pub(super) fn enqueue_identity_recheck_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        if self.vault.config.tagging.is_none() {
            return Ok(());
        }
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: IDENTITY_RECHECK_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{IDENTITY_RECHECK_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )?;
        Ok(())
    }
}

/// One nightly page: each uncertain mention of the page's turns is settled
/// by a hint or opens an ask. The cursor moves past the page, and starts
/// over once a page comes back short.
pub(super) fn run(vault: &Vault, _attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let after = CURSOR.get(&vault.store, txn, &())?;
        let (page, last) =
            crate::tagging::readable_page_in_txn(&vault.store, txn, after.as_ref(), SCAN_TURNS)?;
        let mut open = ASKS.scan(&vault.store, txn)?;
        for tags in &page {
            recheck_turn_in_txn(vault, txn, &tags.turn, &mut open, now)?;
        }
        match last {
            Some(last) if page.len() == SCAN_TURNS => CURSOR.put(&vault.store, txn, &(), &last)?,
            _ => {
                CURSOR.delete(&vault.store, txn, &())?;
            }
        }
        Ok(())
    })
}

impl Vault {
    /// Open asks the host decides now, act-now ones first, up to `limit`,
    /// as 64 hex: none sent to the person yet, none kept separate, none
    /// waiting on a retry.
    pub fn identity_asks_due(&self, now: u64, limit: usize) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        let mut due: Vec<(bool, u64, [u8; 32])> = ASKS
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|(_, ask)| {
                ask.escalated_at.is_none() && ask.kept_separate_at.is_none() && ask.retry_at <= now
            })
            .map(|(key, ask)| {
                let later = !matches!(ask.reason, IdentityAskReason::ActNow { .. });
                (later, ask.opened_at, key)
            })
            .collect();
        due.sort_unstable();
        Ok(due
            .into_iter()
            .take(limit)
            .map(|(_, _, key)| key_hex(&key))
            .collect())
    }

    /// Every open ask, as the owner reads it.
    pub fn identity_asks(&self) -> Result<Vec<IdentityAskView>> {
        let txn = self.store.env.read_txn()?;
        ASKS.scan(&self.store, &txn)?
            .iter()
            .map(|(key, ask)| view_in_txn(self, &txn, key, ask))
            .collect()
    }

    /// One open ask's choice card, worded by `copy`.
    pub fn identity_card(&self, ask: &str, copy: &IdentityCardCopy) -> Result<GeneratedUiCard> {
        let key = parse_key(ask).ok_or_else(|| invalid("the ask is 64 hex"))?;
        let txn = self.store.env.read_txn()?;
        let held = ASKS
            .get(&self.store, &txn, &key)?
            .ok_or_else(|| invalid("no such open ask"))?;
        let options = options_in_txn(self, &txn, &held)?;
        card(&key, &held, &options, copy)
    }

    /// Asks one open ask on the host's ladder: a Choice over its candidates
    /// and [`SOMEONE_NEW`]. A choice settles the mention and saves the hint.
    /// Anything else keeps a nightly ask's names separate for now, with the
    /// Dreamer's receipt, and sends an act-now ask to the person. A failed
    /// call waits [`RETRY_SECS`]. An act-now ask is an outbound effect's
    /// question; a nightly one a reversible read's, as a later answer can
    /// move it.
    pub fn decide_identity_ask(
        &self,
        decisions: &IdentityDecisions<'_>,
        ask: &str,
        now: u64,
    ) -> Result<IdentityRuling> {
        let key = parse_key(ask).ok_or_else(|| invalid("the ask is 64 hex"))?;
        let txn = self.store.env.read_txn()?;
        let Some(held) = ASKS.get(&self.store, &txn, &key)? else {
            return Ok(IdentityRuling::Gone);
        };
        let options = options_in_txn(self, &txn, &held)?;
        let hints = hints_in_txn(self, &txn, held.kind, &held.name)?;
        drop(txn);
        let candidates: Vec<serde_json::Value> = options
            .iter()
            .filter(|option| option.entity.is_some())
            .map(|option| {
                let known = option
                    .entity
                    .as_deref()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .and_then(|id| hints.get(&id))
                    .map(|hint| hint.context.clone());
                json!({
                    "option": option.choice,
                    "name": option.label,
                    "provisional": option.provisional,
                    "known_context": known,
                })
            })
            .collect();
        let effect = match held.reason {
            IdentityAskReason::ActNow { effect } => Some(effect),
            IdentityAskReason::Unsettled => None,
        };
        let mut state = json!({
            "name": held.name,
            "excerpt": held.excerpt,
            "context": held.context,
            "act_now": effect,
            "someone_new": SOMEONE_NEW,
            "candidates": candidates,
        });
        let fits = |state: &serde_json::Value| {
            serde_json::to_vec(state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES)
        };
        if !fits(&state) {
            state["excerpt"] = json!("");
        }
        let kind = [held.kind];
        let question = IDENTITY_SETTLE.question(
            &[kind.as_slice()],
            decisions.wording.clone(),
            AnswerContract::Choice {
                options: options.iter().map(|option| option.choice.clone()).collect(),
            },
        )?;
        let reversibility = if effect.is_some() {
            Reversibility::OutboundEffect
        } else {
            Reversibility::ReversibleRead
        };
        let answer = if fits(&state) {
            match decisions.ladder.run(
                &question,
                decisions.principal,
                &[held.turn, held.message],
                &state,
                decisions.dial,
                &decisions.bands,
                reversibility,
                decisions.deadline,
            ) {
                Ok(decision) => match &decision.answer {
                    DecisionAnswer::Choice(choice) => parse_choice(&held, choice),
                    _ => None,
                },
                Err(_) => {
                    self.with_write_txn_grouped(|txn| {
                        if let Some(mut row) = ASKS.get(&self.store, txn, &key)? {
                            row.retry_at = now.saturating_add(RETRY_SECS);
                            ASKS.put(&self.store, txn, &key, &row)?;
                        }
                        Ok(())
                    })?;
                    return Ok(IdentityRuling::Retry);
                }
            }
        } else {
            None
        };
        self.with_write_txn_grouped(|txn| {
            let Some(current) = ASKS.get(&self.store, txn, &key)? else {
                return Ok(IdentityRuling::Gone);
            };
            if current.candidates != held.candidates
                || current.escalated_at.is_some()
                || current.kept_separate_at.is_some()
            {
                return Ok(IdentityRuling::Gone);
            }
            match answer {
                Some(answer) => Ok(IdentityRuling::Settled(settle_ask_in_txn(
                    self,
                    txn,
                    &key,
                    &current,
                    answer,
                    ClaimSource::Inferred,
                    now,
                )?)),
                None if current.reason == IdentityAskReason::Unsettled => {
                    keep_separate_in_txn(self, txn, &key, current, now)?;
                    Ok(IdentityRuling::KeptSeparate)
                }
                None => {
                    escalate_in_txn(self, txn, &key, current, now)?;
                    Ok(IdentityRuling::NeedsPerson)
                }
            }
        })
    }

    /// Sends each ask that waits on the person again where its name was
    /// said since: one more inbox Ask in the conversation of the newest turn
    /// that mentions the name. Returns how many went.
    pub fn resurface_identity_asks(&self, now: u64) -> Result<usize> {
        let waiting: Vec<([u8; 32], IdentityAsk)> = {
            let txn = self.store.env.read_txn()?;
            ASKS.scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, ask)| ask.escalated_at.is_some())
                .collect()
        };
        let mut sent = 0;
        for (key, ask) in waiting {
            let since = ask.surfaced_turn.unwrap_or(ask.turn);
            let Some(newest) = self
                .tagged_mentions_of_name(ask.kind, &ask.name)?
                .into_iter()
                .map(|hit| hit.turn)
                .filter(|turn| *turn > since)
                .max()
            else {
                continue;
            };
            let moved = self.with_write_txn_grouped(|txn| {
                let Some(mut current) = ASKS.get(&self.store, txn, &key)? else {
                    return Ok(false);
                };
                if current.surfaced_turn.is_some_and(|turn| turn >= newest) {
                    return Ok(false);
                }
                current.surfaced_turn = Some(newest);
                ASKS.put(&self.store, txn, &key, &current)?;
                notify_in_txn(self, txn, &key, &newest, now)?;
                Ok(true)
            })?;
            sent += usize::from(moved);
        }
        Ok(sent)
    }

    /// The owner's answer to one open ask, from the needs-you strip.
    pub fn answer_identity_ask(
        &self,
        owner: &AuthenticatedOwner,
        ask: &str,
        choice: &str,
        now: u64,
    ) -> Result<IdentitySettled> {
        let key = parse_key(ask).ok_or_else(|| invalid("the ask is 64 hex"))?;
        self.with_write_txn_grouped(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            let held = ASKS
                .get(&self.store, txn, &key)?
                .ok_or_else(|| invalid("no such open ask"))?;
            let answer = parse_choice(&held, choice)
                .ok_or_else(|| invalid("not one of the ask's options"))?;
            let entity =
                settle_ask_in_txn(self, txn, &key, &held, answer, ClaimSource::UserStated, now)?;
            Ok(IdentitySettled {
                ask: key_hex(&key),
                entity: entity.to_hex(),
            })
        })
    }
}

impl Memory<'_> {
    /// `self.identity.answer`: an owner's tap on a choice card. Only a vault
    /// owner answers who the people in their conversations are.
    pub fn identity_answer(&self, input: &IdentityAnswerRequest) -> MemoryResult<IdentitySettled> {
        let key = parse_key(&input.ask)
            .ok_or_else(|| MemoryError::bad_request("ask is 64 hex: an open identity ask"))?;
        let now = self.vault().now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            if !crate::policy_model::owners_in_txn(self.vault(), txn)?.contains(&self.actor()) {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "only a vault owner answers an identity ask",
                    &["Answer from the owner's own session."],
                ));
            }
            let held = ASKS
                .get(&self.vault().store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such open identity ask"))?;
            let answer = parse_choice(&held, &input.choice).ok_or_else(|| {
                MemoryError::bad_request("choice is one of the ask's options or someone_new")
            })?;
            let entity = settle_ask_in_txn(
                self.vault(),
                txn,
                &key,
                &held,
                answer,
                ClaimSource::UserStated,
                now,
            )?;
            Ok(IdentitySettled {
                ask: key_hex(&key),
                entity: entity.to_hex(),
            })
        })
    }

    /// `self.identity.settle`: before an agent sends to, pays, invites or
    /// shares with a person it knows by a name, the newest saved mention of
    /// that name (in the conversation, when one is named) says who it is. A
    /// mention that names one entity, or that a hint settles, answers at
    /// once. An uncertain one opens an act-now ask the host decides first;
    /// once that reaches the person, the answer carries their choice card.
    pub fn identity_act_now(&self, input: &IdentityActNowRequest) -> MemoryResult<IdentityActNow> {
        let name = input.name.trim();
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(MemoryError::bad_request(format!(
                "name is 1..={MAX_NAME_BYTES} bytes"
            )));
        }
        let conversation = input
            .conversation
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| MemoryError::bad_request("conversation is 32 hex"))?;
        let copy = IdentityCardCopy {
            prompt: input.prompt.clone(),
            someone_new: input.someone_new.clone(),
            provisional: None,
        };
        let vault = self.vault();
        let hits = vault.tagged_mentions_of_name(ENTITY_TYPE_PERSON, name)?;
        let now = vault.now_recorded_at();
        let effect = input.effect;
        self.with_verified_actor_write_txn(|txn| {
            let mut newest: Option<&crate::tagging::MentionHit> = None;
            for hit in &hits {
                if let Some(conversation) = &conversation
                    && crate::conversation_dag::conversation_of(&vault.store, txn, &hit.turn).ok()
                        != Some(*conversation)
                {
                    continue;
                }
                if newest.is_none_or(|held| hit.turn > held.turn) {
                    newest = Some(hit);
                }
            }
            let Some(hit) = newest else {
                return Ok(IdentityActNow::Unknown);
            };
            let mention = &hit.mention;
            let key = ask_key(&hit.turn, &mention.message, mention.start, mention.end);
            if let Some(mut held) = ASKS.get(&vault.store, txn, &key)? {
                if held.escalated_at.is_some() {
                    let options = options_in_txn(vault, txn, &held)?;
                    let card = serde_json::to_value(card(&key, &held, &options, &copy)?)
                        .map_err(|_| invalid("choice card encoding"))?;
                    return Ok(IdentityActNow::NeedsPerson {
                        ask: key_hex(&key),
                        card,
                    });
                }
                // A nightly ask, kept separate or not, is taken up for the
                // effect: decided now as an outbound effect's question.
                if held.reason == IdentityAskReason::Unsettled {
                    held.reason = IdentityAskReason::ActNow { effect };
                    held.retry_at = 0;
                    held.kept_separate_at = None;
                    ASKS.put(&vault.store, txn, &key, &held)?;
                }
                return Ok(IdentityActNow::Deciding { ask: key_hex(&key) });
            }
            let current =
                crate::tagging::tag_set_in_txn(&vault.store, txn, &hit.turn)?.and_then(|tags| {
                    tags.mentions.into_iter().find(|each| {
                        each.message == mention.message
                            && each.start == mention.start
                            && each.end == mention.end
                    })
                });
            let Some(current) = current else {
                return Ok(IdentityActNow::Unknown);
            };
            let Some(text) =
                crate::tagging::message_text_in_txn(vault, txn, &hit.turn, &current.message)?
            else {
                return Ok(IdentityActNow::Unknown);
            };
            let Some(ask) = ask_for_mention_in_txn(
                vault,
                txn,
                &hit.turn,
                &current,
                &text,
                IdentityAskReason::ActNow { effect },
                now,
            )?
            else {
                return Ok(match current.link.entities() {
                    [entity] => IdentityActNow::Settled {
                        entity: entity.to_hex(),
                    },
                    _ => IdentityActNow::Unknown,
                });
            };
            if let Some(entity) = hinted_in_txn(vault, txn, &ask)? {
                let entity = apply_in_txn(
                    vault,
                    txn,
                    &ask,
                    Answer::Is(entity),
                    ClaimSource::Inferred,
                    now,
                )?;
                return Ok(IdentityActNow::Settled {
                    entity: entity.to_hex(),
                });
            }
            ASKS.put(&vault.store, txn, &key, &ask)?;
            Ok(IdentityActNow::Deciding { ask: key_hex(&key) })
        })
    }
}
