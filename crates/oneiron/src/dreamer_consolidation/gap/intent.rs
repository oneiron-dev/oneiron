//! The owner's stated intent (FIX 8949; ARCH-0040, ARCH-0026). A Dreamer
//! extraction stays Generated: only the owner's own word mints a UserStated
//! `profile.intent`, the claim the digest's urgent breakthrough reads. One
//! writer lands it, Approved and Active, with his exact words, about him,
//! citing the MESSAGE the words came from when there is one, through the
//! claim Gate, his ownership checked again in the write. Two doors reach it:
//!
//! - his own statement at `/v1/owner/intents` ([`Vault::record_owner_intent`]);
//! - his yes to the optional ask a gap scan raises when one of his turns
//!   states an intent ("I will", "I'll") and nothing followed. The ask quotes
//!   the sentence; a yes lands exactly those words at the scan after it, no
//!   or no answer changes nothing. The words must still read as they were
//!   asked, or nothing lands.

use rmpv::Value;

use super::super::turn_text::{TurnText, dreamer_read, read_turn_text};
use super::{GapTexts, ReflectionGap, ReflectionGapKind};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::{
    AnswerContract, AskRole, AskTo, DecisionAnswer, DecisionAsk, DecisionClass, DecisionQuestion,
    DecisionRung, HolderKind, HumanAskReason, HumanDecisionRequest, ProviderPin,
};
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, TimeRange, Vault};

/// The predicate an owner's stated intent is kept under: the one the urgent
/// digest reads.
const PROFILE_INTENT_PREDICATE: &str = "profile.intent";
/// The intent ask's queue, as its pin names it.
const INTENT_ASK_QUEUE: &str = "dreamer.intent_ask";
const INTENT_ASK_QUEUE_VERSION: &str = "1";
/// The domain an intent ask's question id is derived in, from its TURN and
/// the words it quotes.
const INTENT_QUESTION_DOMAIN: &[u8] = b"oneiron.dreamer.intent_ask.question.v1";
/// The domain the intent a yes lands is derived in, from its ask.
const INTENT_CLAIM_DOMAIN: &[u8] = b"oneiron.dreamer.intent_ask.claim.v1";
/// Asks read per page when the scan looks for answered ones.
const ASK_PAGE: usize = 256;
/// What the gap scan reads as a stated intent, lowercased.
const MARKERS: [&str; 2] = ["i will ", "i'll "];

fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

/// Whose word an intent is.
enum OwnerWord<'a> {
    /// His own statement, on his authenticated proof.
    Intake(&'a AuthenticatedOwner),
    /// His yes to an intent ask, as the actor its door authenticated.
    Answered(EntityId),
}

impl Vault {
    /// The owner states an intent in his own words (FIX 8949): `text`, as he
    /// wrote it, lands as an Approved, Active, UserStated `profile.intent`
    /// about him, citing `message` (a MESSAGE) when he names one. His proof
    /// is checked again in the write. Returns the claim.
    ///
    /// # Errors
    ///
    /// A blank `text`, a `message` that names no MESSAGE, a proof that no
    /// longer holds, a Gate refusal, or storage errors.
    pub fn record_owner_intent(
        &self,
        owner: &AuthenticatedOwner,
        text: &str,
        message: Option<EntityId>,
    ) -> Result<EntityId> {
        let id = self.store.clock.entity_id()?;
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            write_owner_intent_in_txn(self, txn, OwnerWord::Intake(owner), id, text, message, now)
        })
    }
}

/// The one intent writer: `text` as `word`'s owner stated it, at `id`.
fn write_owner_intent_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    word: OwnerWord<'_>,
    id: EntityId,
    text: &str,
    message: Option<EntityId>,
    now: u64,
) -> Result<EntityId> {
    if text.trim().is_empty() {
        return Err(invalid("a stated intent needs words"));
    }
    let (owner, via) = match word {
        OwnerWord::Intake(owner) => (owner.revalidate_in_txn(vault, txn)?, "intake"),
        OwnerWord::Answered(actor) => {
            crate::memory::verify_owner_actor_binding_in_txn(vault, txn, actor)
                .map_err(|_| invalid("the intent's answerer is no live owner"))?;
            (actor, "ask")
        }
    };
    let mut candidate = ClaimCandidate::new(
        PROFILE_INTENT_PREDICATE,
        ClaimSubject::Entity(owner),
        Value::from(text),
        1.0,
    );
    if let Some(message) = message {
        if vault.get_entity_type_in_txn(txn, &message)?
            != Some(crate::registry::ENTITY_TYPE_MESSAGE)
        {
            return Err(invalid("a stated intent cites a MESSAGE"));
        }
        candidate = candidate.with_evidence(encode_consolidation_evidence(
            &ConsolidationEvidenceEnvelope {
                refs: vec![message],
                chain: Vec::new(),
                source_meet: ClaimSource::UserStated,
            },
        ));
    }
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("op"), Value::from("intent.owner_stated")),
            (Value::from("via"), Value::from(via)),
        ]))?,
        ClaimApprovalStatus::Approved,
    );
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply(txn)?;
    Ok(id)
}

/// The sentence of `text` that states an intent: the one holding its first
/// marker, as written, without its surrounding whitespace, as a byte range.
fn intent_sentence(text: &str) -> Option<(usize, usize)> {
    // ASCII lowercasing keeps every byte offset.
    let lower = text.to_ascii_lowercase();
    let at = MARKERS
        .iter()
        .filter_map(|marker| lower.find(marker))
        .min()?;
    let ends = |c: char| matches!(c, '.' | '!' | '?' | '\n');
    let start = text[..at].rfind(ends).map_or(0, |index| index + 1);
    let end = text[at..]
        .find(ends)
        .map_or(text.len(), |index| at + index + 1);
    let sentence = &text[start..end];
    let start = start + (sentence.len() - sentence.trim_start().len());
    let end = end - (sentence.len() - sentence.trim_end().len());
    (start < end).then_some((start, end))
}

/// The ask's question over `words`, the sentence `turn` states its intent in.
fn intent_question(turn: EntityId, words: &str) -> Result<DecisionQuestion> {
    Ok(DecisionQuestion {
        id: EntityId::derive(
            INTENT_QUESTION_DOMAIN,
            &[turn.as_bytes().as_slice(), words.as_bytes()],
        )?,
        version: 1,
        text: format!(
            "Your conversation holds these words: \"{words}\". Keep them as your own stated \
             intent? Yes records exactly these words as your intent; no, or no answer, changes \
             nothing."
        ),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    })
}

/// The MESSAGE the words at `start..end` of `record` came from; none for a
/// TURN's own inline text.
fn intent_message(record: &TurnText, start: usize, end: usize) -> Result<Option<EntityId>> {
    Ok(record
        .spans(Some((start, end)))?
        .first()
        .map(|span| span.message))
}

/// Raises the optional intent ask for each stated intent among a scan's new
/// gaps, `texts` holding the words each was read from. An ask that does not
/// queue is logged and the scan goes on: no ask holds anything.
pub(super) fn ask_stated_intents(vault: &Vault, escalations: &[ReflectionGap], texts: &GapTexts) {
    let turns = escalations
        .iter()
        .filter(|gap| gap.kind == ReflectionGapKind::StatedIntentWithoutAction)
        .flat_map(|gap| gap.evidence_turn_refs.iter());
    for turn in turns {
        let Some(record) = texts.get(turn) else {
            continue;
        };
        if let Err(error) = ask_one(vault, *turn, record) {
            tracing::warn!(
                kind = ?error.kind(),
                code = "intent_ask_not_queued",
                "a stated intent's owner ask was not queued"
            );
        }
    }
}

fn ask_one(vault: &Vault, turn: EntityId, record: &TurnText) -> Result<()> {
    let Some(text) = record.text() else {
        return Ok(());
    };
    let Some((start, end)) = intent_sentence(text) else {
        return Ok(());
    };
    let message = intent_message(record, start, end)?;
    vault.queue_decision_ask(&HumanDecisionRequest {
        question: intent_question(turn, &text[start..end])?,
        principal: crate::vault::embedded_owner_actor_id()?,
        evidence: std::iter::once(turn).chain(message).collect(),
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: INTENT_ASK_QUEUE.to_owned(),
            version: INTENT_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: None,
    })?;
    Ok(())
}

/// Lands each intent ask the owner said yes to and none landed yet, every
/// ask read in pages. A failure is logged by kind and the scan goes on; the
/// next scan tries it again.
pub(super) fn land_answered_intents(vault: &Vault) {
    let mut after = None;
    loop {
        let page = match vault.decision_asks(after, ASK_PAGE, false) {
            Ok(page) => page,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    code = "intent_asks_unread",
                    "the answered intent asks were not read"
                );
                return;
            }
        };
        let Some(last) = page.last() else {
            return;
        };
        after = Some(last.seq);
        for ask in &page {
            if let Err(error) = land_answer(vault, ask) {
                tracing::warn!(
                    kind = ?error.kind(),
                    code = "intent_answer_not_landed",
                    "an owner's yes to an intent ask did not land"
                );
            }
        }
    }
}

/// Lands `ask`'s intent when it is an intent ask the owner answered yes, as a
/// person and the owner, and its words still read as they were asked.
fn land_answer(vault: &Vault, ask: &DecisionAsk) -> Result<()> {
    if ask.queue_pin.model != INTENT_ASK_QUEUE {
        return Ok(());
    }
    let Some(answer) = &ask.answer else {
        return Ok(());
    };
    let Some(by) = answer.by.id() else {
        return Ok(());
    };
    if answer.answer != DecisionAnswer::Noul(true)
        || answer.kind != HolderKind::Person
        || answer.role != AskRole::Owner
    {
        return Ok(());
    }
    let Some(&turn) = ask.evidence.first() else {
        return Ok(());
    };
    let id = EntityId::derive(INTENT_CLAIM_DOMAIN, &[ask.id.as_bytes().as_slice()])?;
    if vault.get_entity_type(&id)?.is_some() {
        return Ok(());
    }
    let record = read_turn_text(vault, &turn)?;
    let Some(text) = record.text() else {
        return Ok(());
    };
    let Some((start, end)) = intent_sentence(text) else {
        return Ok(());
    };
    let words = &text[start..end];
    if intent_question(turn, words)?.id != ask.question.id {
        return Ok(());
    }
    let message = intent_message(&record, start, end)?;
    let read = dreamer_read(vault)?;
    let now = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        if vault.get_entity_type_in_txn(txn, &id)?.is_some() {
            return Ok(());
        }
        // The words still stand in this write, at its own clock.
        crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        record.check_live_in(&read, txn, &turn)?;
        write_owner_intent_in_txn(vault, txn, OwnerWord::Answered(by), id, words, message, now)?;
        Ok(())
    })
}
