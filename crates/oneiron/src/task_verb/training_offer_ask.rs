//! A pending training offer asked as a real `tasks.ask` (OF-577, FIX 856).
//!
//! The Coach asks each owner about each pending offer in its own name: one
//! short pointer witnessed as a System TURN in that owner's private
//! conversation with the Coach, and an ask on that TURN that offers the one
//! approval fitting the candidate beside keep, decline and postpone, and
//! holds by default. The TURN and MESSAGE ids are reserved once per offer,
//! owner and digest, so a retry lands the same question and the nightly pass
//! replays the same ask; a new offer has a new digest and is asked afresh.
//!
//! Only the vault owner's own word settles the offer, through the offer's
//! settlement door, in the ask's settling commit: a Human word under the
//! live proof of the owner it asked, given on the node that admitted the
//! ask, naming one of its options while the offer still waits at the asked
//! digest. A deadline, default, abstention, or agent or companion word
//! approves nothing, and the offer stays pending. An answer by any door cuts
//! the offer's other open asks Stale.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ask_record::{self, AskGroup};
use super::ask_types::{
    TaskAskDecision, TaskAskDefault, TaskAskEvidenceReason, TaskAskOptionId, TaskAskQuestion,
    TaskAskResult, TaskAskSettlementReason, TaskAskSource, TaskAskSpec, TaskAskTarget, TaskAskWord,
};
use super::{ConsultPayloadRef, TaskAssignee};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{EvalSeat, OfferAnswer, OfferCandidate, TrainingOffer};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// Every training offer ask's intent key starts so:
/// `training_offer/<offer hex>/<digest>/<owner hex>`.
const INTENT_PREFIX: &str = "training_offer/";
/// The message type of the witnessed question.
pub(crate) const OFFER_QUESTION_TYPE: &str = "training_offer_question";
/// The question message's metadata keys: the offer tuple. It locates the
/// reservation and proves nothing by itself.
const META_OFFER: &str = "training_offer";
const META_DIGEST: &str = "training_offer_digest";
const META_OWNER: &str = "training_offer_owner";

/// The options an offer ask may carry: stable id, the answer it settles and
/// its label. One approval fits each candidate.
const OPTIONS: [(&str, OfferAnswer, &str); 5] = [
    (
        "approve_switch",
        OfferAnswer::ApproveSwitch,
        "Switch to the offered model",
    ),
    (
        "approve_train",
        OfferAnswer::ApproveTrain,
        "Train the custom model",
    ),
    (
        "keep_baseline",
        OfferAnswer::KeepBaseline,
        "Keep today's setup",
    ),
    ("decline", OfferAnswer::Decline, "Decline the offer"),
    ("postpone", OfferAnswer::Postpone, "Ask again later"),
];

/// `(offer, owner, offer digest)`: one owner asked about one offer snapshot.
type OfferAskKey = (EntityId, EntityId, String);

/// One owner's question about one offer: ids and time reserved before the
/// witness, and the ask group once admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferAskRoute {
    offer: EntityId,
    digest: String,
    owner: EntityId,
    conversation: EntityId,
    turn: EntityId,
    message: EntityId,
    at: u64,
    group: Option<EntityId>,
}

/// The ids one offer question was reserved under.
pub(crate) struct ReservedQuestion {
    pub(crate) conversation: EntityId,
    pub(crate) turn: EntityId,
    pub(crate) message: EntityId,
}

/// `(offer, owner, digest)` → that owner's question about that offer.
const ASKS: SideTable<OfferAskKey, OfferAskRoute, Named> =
    SideTable::new(&side_table::TASK_TRAINING_OFFER_ASK);

/// `ask group` → the reservation it carries.
const GROUPS: SideTable<EntityId, OfferAskKey, Named> =
    SideTable::new(&side_table::TASK_TRAINING_OFFER_ASK_GROUP);

fn owner_not_authenticated(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// Who asks the owner about a training offer: the Coach, in its own name
/// (Engine ruling 10-18). It never speaks or asks as the owner.
fn offer_ask_issuer(vault: &Vault) -> Result<WriteActor> {
    vault.coach_authority()
}

/// Whether `intent_key` is a training offer ask's. The prefix admits
/// nothing by itself: a routed ask is one its group index names.
pub(crate) fn is_training_offer_ask_intent(intent_key: &str) -> bool {
    intent_key.starts_with(INTENT_PREFIX)
}

fn ask_key(offer: &TrainingOffer, owner: EntityId) -> OfferAskKey {
    (offer.id, owner, offer.digest.clone())
}

fn intent_key(key: &OfferAskKey) -> String {
    let (offer, owner, digest) = key;
    format!(
        "{INTENT_PREFIX}{}/{digest}/{}",
        offer.to_hex(),
        owner.to_hex()
    )
}

fn canonical_id(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

fn canonical_digest(digest: &str) -> Option<String> {
    let lower_hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    (digest.len() == 64 && digest.bytes().all(lower_hex)).then(|| digest.to_owned())
}

/// The offer tuple a training offer ask's intent key names, read whole and
/// in canonical form; `None` for any other key.
pub(crate) fn training_offer_ask_key(intent_key: &str) -> Option<OfferAskKey> {
    let mut parts = intent_key.strip_prefix(INTENT_PREFIX)?.split('/');
    let (Some(offer), Some(digest), Some(owner), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some((
        canonical_id(offer)?,
        canonical_id(owner)?,
        canonical_digest(digest)?,
    ))
}

/// The one string `entries` holds under `name`; `None` when absent, repeated
/// or not a string.
fn single_str<'a>(entries: &'a [(rmpv::Value, rmpv::Value)], name: &str) -> Option<&'a str> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value.as_str());
    match (values.next(), values.next()) {
        (Some(value), None) => value,
        _ => None,
    }
}

/// The offer tuple a question message's metadata names: exactly the three
/// keys the Coach writes, each once, in canonical form.
pub(crate) fn offer_question_key(metadata: &rmpv::Value) -> Option<OfferAskKey> {
    let rmpv::Value::Map(entries) = metadata else {
        return None;
    };
    if entries.len() != 3 {
        return None;
    }
    Some((
        canonical_id(single_str(entries, META_OFFER)?)?,
        canonical_id(single_str(entries, META_OWNER)?)?,
        canonical_digest(single_str(entries, META_DIGEST)?)?,
    ))
}

fn offer_question_metadata(key: &OfferAskKey) -> serde_json::Value {
    let (offer, owner, digest) = key;
    let mut metadata = serde_json::Map::new();
    metadata.insert(META_OFFER.to_owned(), offer.to_hex().into());
    metadata.insert(META_DIGEST.to_owned(), digest.clone().into());
    metadata.insert(META_OWNER.to_owned(), owner.to_hex().into());
    serde_json::Value::Object(metadata)
}

/// The witnessed question: one short pointer to the offer card, never its
/// numbers.
pub(crate) fn offer_question_text(offer: &TrainingOffer) -> String {
    let seat = match &offer.seat {
        EvalSeat::Companion => "companion",
        EvalSeat::Decision => "decision",
        EvalSeat::ExtractionTagger => "extraction tagger",
        EvalSeat::Embedder => "embedder",
        EvalSeat::Router => "router",
        EvalSeat::Named(name) => name.as_str(),
    };
    let change = match &offer.candidate {
        OfferCandidate::Stock { model, .. } => format!("switch to {}", model.model),
        OfferCandidate::TrainRecipe { .. } => "train a custom model".to_owned(),
    };
    format!(
        "The Coach has a training offer for your {seat} seat: {change}. Doing nothing keeps \
         today's setup. The offer card has the cost and the scores."
    )
}

/// Whether `answer` is offered for `candidate`: the one approval that fits
/// it, and keep, decline and postpone always.
fn fits(candidate: &OfferCandidate, answer: OfferAnswer) -> bool {
    match answer {
        OfferAnswer::ApproveSwitch => matches!(candidate, OfferCandidate::Stock { .. }),
        OfferAnswer::ApproveTrain => matches!(candidate, OfferCandidate::TrainRecipe { .. }),
        OfferAnswer::KeepBaseline | OfferAnswer::Decline | OfferAnswer::Postpone => true,
    }
}

/// The answer `option` settles on `offer`, when an ask on it offers that
/// option.
fn offered_answer(offer: &TrainingOffer, option: &TaskAskOptionId) -> Option<OfferAnswer> {
    OPTIONS
        .iter()
        .find(|(id, answer, _)| *id == option.as_str() && fits(&offer.candidate, *answer))
        .map(|(_, answer, _)| *answer)
}

/// The ask on `turn` that asks the owner of `key` about `offer`.
fn offer_ask_spec(
    offer: &TrainingOffer,
    key: &OfferAskKey,
    turn: EntityId,
) -> MemoryResult<TaskAskSpec> {
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(turn));
    let mut options = BTreeMap::new();
    for (id, answer, label) in OPTIONS {
        if fits(&offer.candidate, answer) {
            options.insert(TaskAskOptionId::new(id)?, label.to_owned());
        }
    }
    what.options = options;
    let who = TaskAskTarget::Responder(TaskAssignee::Human { actor_ref: key.1 });
    let mut spec = TaskAskSpec::shorthand(Some(who), what, None, TaskAskDefault::Hold);
    spec.intent_key = intent_key(key);
    Ok(spec)
}

/// The ids reserved for the question `key` names, if any.
/// # Errors
/// Storage errors.
pub(crate) fn reserved_offer_question_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &OfferAskKey,
) -> Result<Option<ReservedQuestion>> {
    Ok(ASKS
        .get(&vault.store, txn, key)?
        .map(|route| ReservedQuestion {
            conversation: route.conversation,
            turn: route.turn,
            message: route.message,
        }))
}

/// The reservation for `key`, its ids minted on first use. An owner's later
/// questions share the conversation of the first.
fn reserve(vault: &Vault, key: &OfferAskKey, now: u64) -> Result<OfferAskRoute> {
    vault.with_write_txn_grouped(|txn| {
        if let Some(route) = ASKS.get(&vault.store, txn, key)? {
            return Ok(route);
        }
        let (offer, owner, digest) = key;
        let conversation = match ASKS
            .scan(&vault.store, txn)?
            .into_iter()
            .find(|(_, route)| route.owner == *owner)
        {
            Some((_, route)) => route.conversation,
            None => vault.store.clock.entity_id()?,
        };
        let route = OfferAskRoute {
            offer: *offer,
            digest: digest.clone(),
            owner: *owner,
            conversation,
            turn: vault.store.clock.entity_id()?,
            message: vault.store.clock.entity_id()?,
            at: now,
            group: None,
        };
        ASKS.put(&vault.store, txn, key, &route)?;
        Ok(route)
    })
}

/// Binds `group` to the reservation `key` and indexes it, once.
fn bind_group_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &OfferAskKey,
    group: EntityId,
) -> Result<()> {
    let mut route = ASKS
        .get(&vault.store, txn, key)?
        .ok_or_else(ask_record::invalid)?;
    if route.group.is_none() {
        route.group = Some(group);
        ASKS.put(&vault.store, txn, key, &route)?;
        GROUPS.put(&vault.store, txn, &group, key)?;
    }
    Ok(())
}

/// Each pending offer with the owners not asked about it yet.
fn unasked(vault: &Vault) -> Result<Vec<(TrainingOffer, Vec<EntityId>)>> {
    let offers = crate::skill_optimize::pending_training_offers(vault)?;
    if offers.is_empty() {
        return Ok(Vec::new());
    }
    let txn = vault.store.env.read_txn()?;
    let owners = crate::policy_model::owners_in_txn(vault, &txn)?;
    let mut unasked = Vec::new();
    for offer in offers {
        let mut left = Vec::new();
        for owner in &owners {
            if !ASKS
                .get(&vault.store, &txn, &ask_key(&offer, *owner))?
                .is_some_and(|route| route.group.is_some())
            {
                left.push(*owner);
            }
        }
        if !left.is_empty() {
            unasked.push((offer, left));
        }
    }
    Ok(unasked)
}

/// Asks `owner` about `offer` as `issuer`: reserves the question, witnesses
/// it unless it already landed, and admits the ask with its group bound in
/// the admission's commit. Returns whether this call admitted a new ask.
fn issue_one(
    vault: &Vault,
    issuer: &Memory<'_>,
    offer: &TrainingOffer,
    owner: EntityId,
    now: u64,
) -> MemoryResult<bool> {
    let key = ask_key(offer, owner);
    let route = reserve(vault, &key, now)?;
    if route.group.is_some() {
        return Ok(false);
    }
    let landed = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        vault
            .get_entity_type_in_txn(&txn, &route.message)?
            .is_some()
    };
    if !landed {
        issuer.witness(&WitnessTurn {
            conversation_ref: route.conversation.to_hex(),
            turn_ref: Some(route.turn.to_hex()),
            quote: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(route.message.to_hex()),
                author: WitnessAuthor::System,
                message_type: OFFER_QUESTION_TYPE.to_owned(),
                content: offer_question_text(offer),
                metadata: Some(offer_question_metadata(&key)),
                is_visible: true,
                order: 0,
            }],
            occurred_at: route.at,
            assertions: Default::default(),
        })?;
    }
    let spec = offer_ask_spec(offer, &key, route.turn)?;
    let receipt = issuer.tasks_ask_with_txn_effect(&spec, |txn, group| {
        bind_group_in(vault, txn, &key, group).map_err(MemoryError::from)
    })?;
    if receipt.idempotent_replay {
        vault.with_write_txn_grouped(|txn| {
            bind_group_in(vault, txn, &key, receipt.handle.group_ref)
        })?;
    }
    Ok(!receipt.idempotent_replay)
}

/// Asks every owner about every pending offer they were not asked about yet,
/// as the Coach. Returns how many asks this pass admitted, and never fails
/// its caller: a refusal (the Coach's reach revoked) is logged quietly and
/// the next tuple goes on. The inbox notification and the digest deliver the
/// offer either way.
pub(crate) fn issue_training_offer_asks(vault: &Vault, now: u64) -> usize {
    let unasked = match unasked(vault) {
        Ok(unasked) => unasked,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "training offer asks not read");
            return 0;
        }
    };
    if unasked.is_empty() {
        return 0;
    }
    let issuer = match offer_ask_issuer(vault) {
        Ok(issuer) => issuer,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "training offer ask issuer not resolved");
            return 0;
        }
    };
    let memory = vault.memory(issuer.entity_ref(), issuer.actor_class());
    let mut issued = 0;
    for (offer, owners) in &unasked {
        for owner in owners {
            match issue_one(vault, &memory, offer, *owner, now) {
                Ok(true) => issued += 1,
                Ok(false) => {}
                Err(error) if error.code == MEMORY_CODE_FORBIDDEN => {
                    tracing::debug!(
                        offer = %offer.id.to_hex(),
                        code = %error.code,
                        "training offer ask refused"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        offer = %offer.id.to_hex(),
                        code = %error.code,
                        "training offer ask not issued"
                    );
                }
            }
        }
    }
    issued
}

/// The reservation an ask group carries, when the Coach's issuance bound
/// it; `None` for every other ask. A bound group whose reservation does not
/// name it back fails closed.
fn routed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Option<OfferAskRoute>> {
    if !is_training_offer_ask_intent(&group.requested.intent_key) {
        return Ok(None);
    }
    let Some(key) = GROUPS.get(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let route = ASKS
        .get(&vault.store, txn, &key)?
        .filter(|route| route.group == Some(id) && intent_key(&key) == group.requested.intent_key)
        .ok_or_else(ask_record::invalid)?;
    Ok(Some(route))
}

/// Refuses a word on a training offer ask unless it is the asked owner's own
/// act; any other ask passes untouched. Runs in shared word admission,
/// before the word is recorded, beside `attendee_answer::guard_word`.
#[expect(
    clippy::too_many_arguments,
    reason = "one admission check over the word, its writer and the owner proof"
)]
pub(super) fn guard_word(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: TaskAskSource,
    actor: EntityId,
    word: &TaskAskWord,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    let Some(route) = routed_in(vault, txn, id, group)? else {
        return Ok(());
    };
    // The owner's own tap, never a word given for them or a soft confirm.
    if word.companion_for.is_some() || word.inform_for.is_some() || word.confirmation.is_some() {
        return Err(ask_record::invalid());
    }
    // A definitive answer names one option the ask offered, while the offer
    // still waits at the asked digest.
    let offer = crate::skill_optimize::pending_training_offer_in_txn(vault, txn, &route.offer)?
        .filter(|offer| offer.digest == route.digest)
        .ok_or_else(ask_record::invalid)?;
    if word
        .option
        .as_ref()
        .and_then(|option| offered_answer(&offer, option))
        .is_none()
    {
        return Err(ask_record::invalid());
    }
    // Only the admission node settles the ask, so a word anywhere else
    // could never settle under the proof that admitted it.
    if !ask_record::owns_revision(vault, txn, id, group)? {
        return Err(owner_not_authenticated(
            "a training offer answer is given on the node that admitted the ask",
        ));
    }
    let Some(owner) = owner else {
        return Err(owner_not_authenticated(
            "a training offer answer needs the owner's own authenticated word",
        ));
    };
    let proven = owner.revalidate_in_txn(vault, txn)?;
    if source != TaskAskSource::Human || proven != actor || proven != route.owner {
        return Err(owner_not_authenticated(
            "a training offer answer is the asked owner's own word",
        ));
    }
    Ok(())
}

/// Whether settlement may cut the ask `id` for `reason` with `decision`
/// under `owner`. A training offer ask's first word settles the offer only
/// under the live proof of the owner it asked; without that proof the ask
/// stays open, and only its deadline or staleness closes it, on the hold
/// default.
pub(super) fn may_cut(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    reason: TaskAskSettlementReason,
    decision: &TaskAskDecision,
    owner: Option<&AuthenticatedOwner>,
) -> Result<bool> {
    if matches!(
        reason,
        TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale
    ) {
        return Ok(true);
    }
    let Some(route) = routed_in(vault, txn, id, group)? else {
        return Ok(true);
    };
    let TaskAskDecision::First(answer) = decision else {
        return Ok(true);
    };
    match owner {
        Some(owner) => {
            let proven = owner.revalidate_in_txn(vault, txn)?;
            Ok(proven == answer.actor_ref && proven == route.owner)
        }
        None => Ok(false),
    }
}

/// Settles the offer from the word `result` selected, in the ask's settling
/// transaction, before the settlement is stored.
///
/// It acts only on a definitive cut of a training offer ask: a counted Human
/// word selected First, coverage met, no fallback, not stale, live owner
/// proof naming that word's actor and the asked owner, and the offer still
/// waiting at the asked digest. The answer is that word's own option. An
/// offer answered elsewhere first stands; every other case is a no-op, never
/// an approval.
pub(super) fn resolve_answer_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: &AskGroup,
    result: &TaskAskResult,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    let id = result.settlement.group_ref;
    let Some(route) = routed_in(vault, txn, id, group)? else {
        return Ok(());
    };
    let (TaskAskDecision::First(answer), Some(owner)) = (&result.decision, owner) else {
        return Ok(());
    };
    if !result.coverage.met
        || result.fallback.is_some()
        || result.settlement.reason == TaskAskSettlementReason::Stale
    {
        return Ok(());
    }
    let proven = owner.revalidate_in_txn(vault, txn)?;
    if proven != answer.actor_ref || proven != route.owner {
        return Ok(());
    }
    let Some(selected) = result.evidence.iter().find(|entry| {
        entry.answer == *answer
            && entry.reason == TaskAskEvidenceReason::Counted
            && entry.source == TaskAskSource::Human
    }) else {
        return Ok(());
    };
    let Some(offer) =
        crate::skill_optimize::pending_training_offer_in_txn(vault, txn, &route.offer)?
            .filter(|offer| offer.digest == route.digest)
    else {
        return Ok(());
    };
    let Some(choice) = selected
        .word
        .option
        .as_ref()
        .and_then(|option| offered_answer(&offer, option))
    else {
        return Ok(());
    };
    crate::skill_optimize::settle_training_offer_in_txn(
        vault,
        txn,
        owner,
        &route.offer,
        &route.digest,
        choice,
        result.settlement.at,
        Some(&id),
    )?;
    Ok(())
}

/// Cuts every other still-open ask for `offer` Stale in `txn` once an answer
/// settled it, so its words settle nothing and it stops waiting for its
/// deadline. `except` is the ask whose own settlement carries the answer. A
/// held ask, or one another node admitted, keeps to its deadline; its words
/// are refused, since the offer no longer waits. A Stale cut decides
/// nothing, so it never settles the offer again.
/// # Errors
/// Storage errors, or a cut that fails.
pub(crate) fn void_training_offer_asks_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    offer: &EntityId,
    except: Option<&EntityId>,
    now: u64,
) -> Result<()> {
    for (_, route) in ASKS.scan_from(&vault.store, txn, offer.as_bytes())? {
        let Some(group) = route.group else {
            continue;
        };
        if except == Some(&group)
            || super::ask_settlement::read_result(vault, txn, group)?.is_some()
        {
            continue;
        }
        let Some(asked) = ask_record::read_group(vault, txn, group)? else {
            continue;
        };
        if ask_record::owns_revision(vault, txn, group, &asked)? {
            super::ask_settlement::void_in(vault, txn, group, now)?;
        }
    }
    Ok(())
}
