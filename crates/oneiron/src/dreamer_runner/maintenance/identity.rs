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
//! The host asks each open ask as one decide() Choice over its candidates,
//! as many as a Choice lists with the rest by id in its state, plus
//! [`SOMEONE_NEW`] ([`Vault::decide_identity_ask`]). A choice settles the
//! mention. An abstention on a nightly ask keeps the names separate for
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
//!
//! The Dreamer's own settles, a saved hint's pick and a decision's choice,
//! apply at once and leave the Dreamer's receipt with what they changed
//! before and after, which the owner reverts into the question to them
//! (FIX 3327); an owner's own answer is his act and leaves none.
//!
//! Every door that lists, renders, decides or answers an ask reads it
//! through its caller's own lane (FIX 8711, [`maintenance_reader`] for the
//! host), and an erase reaches every kept copy of a mention's bytes: asks,
//! hints and the Dreamer's inverses (FIX 8707).
mod admission;
mod erase;
mod evidence;
mod hints;
mod host;
mod presentation;
mod recheck;
mod settle_undo;
mod settlement;
pub use admission::maintenance_reader;
pub(crate) use erase::{erase_actor_sources_in_txn, erase_sources_in_txn};
pub use evidence::{
    IdentityAnswerEvidenceRequest, IdentityMentionState, IdentityMentionView,
    IdentityResolutionView,
};
pub(crate) use evidence::{clear_mention_resolutions_in_txn, erase_mention_resolutions_in_txn};
pub(crate) use hints::hinted_mention_in_txn;
use hints::{hinted_in_txn, put_hint_in_txn};
use presentation::{card, options_in_txn, view_in_txn};
pub(super) use recheck::run;
use recheck::{ask_for_mention_in_txn, context_terms, measure_ask};
pub(super) use settle_undo::{SettleInverse, revert_settle_in_txn};
use settlement::{
    apply_in_txn, ask_answer_id, dreamer_seal, entity_of_kind_in_txn, escalate_in_txn,
    keep_separate_in_txn, listed_candidates, notify_in_txn, parse_choice, settle_ask_in_txn,
};

use serde::{Deserialize, Serialize};

use super::applied::{MaintenanceRevert, MaintenanceTarget};
use crate::authority::ActAuthority;
use crate::claim::{ClaimReadStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::identity_topology::{EngineCause, TopologySeal};
use crate::limit_ask::EngineLimit;
use crate::llm::decision::{DecisionBandPolicy, DecisionDial, DecisionLadder};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
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
/// Open asks at once, besides those kept separate: a pace. Past this a pass
/// stops at the turn that would open one, and the next pass starts there.
const MAX_OPEN_ASKS: usize = 64;
/// Candidates one Choice lists beside "someone new"; the rest ride in its
/// state by id.
const MAX_CANDIDATES: usize = 63;
/// Context words one mention keeps.
const MAX_TERMS: usize = 16;
const MIN_TERM_CHARS: usize = 4;
/// How long a failed decision waits before the host tries again.
const RETRY_SECS: u64 = 3_600;
/// The rationale on a someone-new answer's `assert_distinct` event.
const SOMEONE_NEW_RATIONALE: &str = "identity ask: someone new";
/// The context of the id an owner's answer binds its topology decision to
/// (its act's `answer`, mesh PR2-topology): the ask, by its key.
const ASK_ANSWER_CONTEXT: &[u8] = b"oneiron/identity-ask/answer/v1";
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
    /// The entities it may be, real or provisional, every one: a decision
    /// lists as many as its Choice takes and carries the rest by id.
    pub candidates: Vec<EntityId>,
    /// The mention's own provisional entity, when it named only that one and
    /// the name now keys to real people: "someone new" confirms it.
    pub provisional: Option<EntityId>,
    /// The words around the mention, as a hint keeps them.
    pub context: Vec<String>,
    /// The complete source message, for the decision; `start..end` selects
    /// the mention.
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

/// The words answers about a name were given in, summed over the saved
/// contributions a read counts, once each.
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
    /// The ask was answered or changed meanwhile, or the deciding lane does
    /// not read it whole (FIX 8711).
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
    let current =
        crate::tagging::readable_view_in_txn(&vault.store, txn, &turn)?.and_then(|tags| {
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

/// A nightly abstention's inverse: the ask as it stood before the names were
/// kept separate, none once an erase reached its mention (FIX 8707), where
/// that mention is, and when they were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionalInverse {
    prior: Option<IdentityAsk>,
    source: erase::SourceAnchor,
    kept_at: u64,
}

/// The owner's revert of a kept-separate ask: the ask as it stood before
/// goes to them as today's question, an inbox Ask with its choice card, as
/// reverting "keep them separate for now" means "ask me". An ask answered,
/// decided again or taken up for an act-now effect since, one an erase
/// reached, or one whose mention no longer reads as it did is left alone.
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
    let Some(prior) = &inverse.prior else {
        out.left_alone.push(key_hex(&key));
        return Ok(());
    };
    let kept = IdentityAsk {
        kept_separate_at: Some(inverse.kept_at),
        ..prior.clone()
    };
    if ASKS.get(&vault.store, txn, &key)?.as_ref() != Some(&kept)
        || !erase::anchor_reads_in_txn(vault, txn, &inverse.source, &prior.name)?
    {
        out.left_alone.push(key_hex(&key));
        return Ok(());
    }
    escalate_in_txn(vault, txn, &key, prior.clone(), now)?;
    out.asked.push(key_hex(&key));
    Ok(())
}

impl Memory<'_> {
    /// `self.identity.answer`: an owner's tap on a choice card. Only a vault
    /// owner answers who the people in their conversations are. The topology
    /// decision is his, bound to the ask, only when the request bound his own
    /// proof (`owner_authorship`); otherwise it is an engine seal under
    /// [`EngineCause::OwnerAnswerUnproven`]. The actor or its class alone
    /// never authenticates an owner.
    pub fn identity_answer(&self, input: &IdentityAnswerRequest) -> MemoryResult<IdentitySettled> {
        self.identity_answer_guarded(input, self.owner_authorship(), &[])
    }

    fn identity_answer_guarded(
        &self,
        input: &IdentityAnswerRequest,
        owner: Option<&AuthenticatedOwner>,
        owner_evidence: &[EntityId],
    ) -> MemoryResult<IdentitySettled> {
        let key = parse_key(&input.ask)
            .ok_or_else(|| MemoryError::bad_request("ask is 64 hex: an open identity ask"))?;
        // The caller's own lane (FIX 8711), opened before the write: an ask
        // it does not read is no such open ask, and a candidate it does not
        // read is no option.
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let now = self.vault().now_recorded_at();
        let seal = match owner {
            Some(owner) => {
                // Where his request reached this install, as the host bound
                // it (FIX 4650): audit only.
                TopologySeal::decision(ActAuthority::Owner(owner.clone(), self.owner_surface()))
                    .answering(ask_answer_id(&key)?)
            }
            None => TopologySeal::engine(EngineCause::OwnerAnswerUnproven),
        };
        self.with_verified_actor_write_txn(|txn| {
            if let Some(owner) = owner {
                if owner.revalidate_in_txn(self.vault(), txn)? != self.actor() {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "identity answer proof does not name the caller",
                        &["Answer from the owner's own session."],
                    ));
                }
                crate::memory::identity_doors::require_identity_evidence_in_txn(
                    self.vault(),
                    txn,
                    owner_evidence,
                )?;
            }
            if !crate::policy_model::owners_in_txn(self.vault(), txn)?.contains(&self.actor()) {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "only a vault owner answers an identity ask",
                    &["Answer from the owner's own session."],
                ));
            }
            let seen = admission::open_ask_in_txn(self.vault(), &lane, txn, &key, false)?
                .ok_or_else(|| MemoryError::not_found("no such open identity ask"))?;
            let answer = parse_choice(&seen.ask, &input.choice).ok_or_else(|| {
                MemoryError::bad_request("choice is one of the ask's options or someone_new")
            })?;
            let held = seen.stored;
            let entity = settle_ask_in_txn(
                self.vault(),
                txn,
                &key,
                &held,
                answer,
                (ClaimSource::UserStated, &seal),
                now,
            )?;
            if let Some(owner) = owner {
                evidence::prove_owner_in_txn(self.vault(), txn, owner, &held, owner_evidence)?;
            }
            self.produced_from(
                std::iter::once(held.turn)
                    .chain([held.message, entity])
                    .chain(owner_evidence.iter().copied()),
            );
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
        if name.is_empty() {
            return Err(MemoryError::bad_request("name is not empty"));
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
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, name.len() as u64);
        let hits = vault.tagged_mentions_of_name(ENTITY_TYPE_PERSON, name)?;
        // The caller's own lane (FIX 8711): a mention, candidate or hint word
        // it does not read looks absent.
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let now = vault.now_recorded_at();
        let effect = input.effect;
        self.with_verified_actor_write_txn(|txn| {
            let admit = admission::Admit::in_txn(&lane, txn)?;
            let mut newest: Option<&crate::tagging::MentionHit> = None;
            for hit in &hits {
                if let Some(conversation) = &conversation
                    && crate::conversation_dag::conversation_of(&vault.store, txn, &hit.turn).ok()
                        != Some(*conversation)
                {
                    continue;
                }
                if newest.is_none_or(|held| hit.turn > held.turn)
                    && admit.reads_source(txn, &hit.turn, &hit.mention.message)?
                {
                    newest = Some(hit);
                }
            }
            let Some(hit) = newest else {
                return Ok(IdentityActNow::Unknown);
            };
            let mention = &hit.mention;
            let key = ask_key(&hit.turn, &mention.message, mention.start, mention.end);
            if let Some(held) = ASKS.get(&vault.store, txn, &key)? {
                let Some(seen) = admission::admitted_in_txn(vault, &admit, txn, held)? else {
                    return Ok(IdentityActNow::Unknown);
                };
                let mut held = seen.stored;
                if held.escalated_at.is_some() {
                    let options = options_in_txn(vault, txn, &seen.ask)?;
                    let card = serde_json::to_value(card(&key, &seen.ask, &options, &copy)?)
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
            let current = crate::tagging::readable_view_in_txn(&vault.store, txn, &hit.turn)?
                .and_then(|tags| {
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
                // One entity answers only when the lane reads it.
                if let [entity] = current.link.entities()
                    && admission::candidate_in_txn(vault, &admit, txn, entity)?
                {
                    return Ok(IdentityActNow::Settled {
                        entity: entity.to_hex(),
                    });
                }
                return Ok(IdentityActNow::Unknown);
            };
            // The hint's settle answers the agent at once, and leaves the
            // Dreamer's receipt the owner reverts (FIX 3327): only from the
            // candidates and hint words the lane reads, on an ask whose spans
            // it reads.
            if let Some(seen) = admission::admitted_in_txn(vault, &admit, txn, ask.clone())?
                && let Some(entity) = hints::pick(&seen.hints, &seen.ask.candidates, &ask.context)
            {
                let entity = settle_undo::settle_in_txn(
                    vault,
                    txn,
                    &ask,
                    Answer::Is(entity),
                    (ClaimSource::Inferred, &dreamer_seal()),
                    now,
                )?;
                return Ok(IdentityActNow::Settled {
                    entity: entity.to_hex(),
                });
            }
            measure_ask(vault, &ask);
            ASKS.put(&vault.store, txn, &key, &ask)?;
            Ok(IdentityActNow::Deciding { ask: key_hex(&key) })
        })
    }
}
