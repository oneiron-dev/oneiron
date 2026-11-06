//! An owner-judged contribution pair asked as a real `tasks.ask` (FIX 3609).
//!
//! The Coach asks the vault owner about one pending pair in its own name.
//! The question, with the frozen criterion and the task, is witnessed as a
//! TURN the Coach speaks in the owner's conversation with the Coach, and
//! each of the two blinded answers as a TURN of its own there. A new TURN
//! needs a speaker, so each part speaks as the companion, and only the
//! Coach's pair permit lands it. The ask carries the question TURN, with
//! the two answer TURNs as its context, offers five options and holds by
//! default. The pair's own row is its route, bound in
//! the ask's admission by a composed effect, so a held ask binds it as the
//! owner's approval releases it. The TURN and MESSAGE ids are reserved with
//! the pair, so a retry lands the same question and replays the same ask.
//!
//! Only the asked owner's own counted word settles the pair, in the ask's
//! settling commit ([`resolve_answer_in`]): a Human word under the live
//! proof of that owner, at the question digest and revision the ask was
//! admitted with. Word admission refuses any other word on the ask
//! ([`guard_word`]). A card acknowledgement, a companion or executor word,
//! a deadline, a fallback and a stale ask score nothing and close the pair.
//! The Coach's offer-ask reach covers the two acts, as it covers a training
//! offer's: witnessing the pair's reserved parts, and asking the one owner
//! on them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ask_effect::AskEffect;
use super::ask_record::{self, AskGroup};
use super::ask_types::{
    TaskAskDecision, TaskAskDefault, TaskAskEvidenceReason, TaskAskOptionId, TaskAskQuestion,
    TaskAskResult, TaskAskSettlementReason, TaskAskSource, TaskAskSpec, TaskAskTarget, TaskAskWord,
};
use super::training_offer_ask::{canonical_id, single_str};
use super::{ConsultPayloadRef, TaskAssignee};
use crate::code_run::{
    OwnerJudgment, OwnerPair, OwnerPairAnswer, OwnerPairChoice, OwnerPairRoute, OwnerPairTexts,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use crate::{EntityId, Vault};

/// Every contribution pair ask's intent key: `contribution_pair/<handle hex>`.
const INTENT_PREFIX: &str = "contribution_pair/";
/// The message type of each witnessed part of a pair's question.
pub(crate) const CONTRIBUTION_PAIR_QUESTION_TYPE: &str = "contribution_pair_question";
/// A part message's metadata keys: the pair's handle and which part it is.
/// They locate the reservation and prove nothing by themselves.
const META_PAIR: &str = "contribution_pair";
const META_PART: &str = "contribution_pair_part";

/// The route a pair's ask carries: the pair's opaque handle and the question
/// revision it asks at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContributionPairRoute {
    handle: EntityId,
    revision: u64,
}

/// One witnessed part of a pair's question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Question,
    ShownA,
    ShownB,
}

impl Part {
    const ALL: [Self; 3] = [Self::Question, Self::ShownA, Self::ShownB];

    const fn name(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::ShownA => "shown_a",
            Self::ShownB => "shown_b",
        }
    }

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|part| part.name() == name)
    }

    /// Its reserved TURN and MESSAGE ids on `pair`, and the digest of the
    /// text it shows.
    fn ids(self, pair: &OwnerPair) -> (EntityId, EntityId, [u8; 32]) {
        let part = match self {
            Self::Question => &pair.presentation.question,
            Self::ShownA => &pair.presentation.shown_a,
            Self::ShownB => &pair.presentation.shown_b,
        };
        (part.turn, part.message, part.content)
    }

    fn text(self, texts: &OwnerPairTexts) -> &str {
        match self {
            Self::Question => &texts.question,
            Self::ShownA => &texts.shown_a,
            Self::ShownB => &texts.shown_b,
        }
    }
}

/// Whether `intent_key` is a contribution pair ask's. The prefix admits
/// nothing by itself: a routed ask is one its pair's row names.
pub(crate) fn is_contribution_pair_ask_intent(intent_key: &str) -> bool {
    intent_key.starts_with(INTENT_PREFIX)
}

/// The pair handle a contribution pair ask's intent key names, in canonical
/// form; `None` for any other key.
fn pair_handle(intent_key: &str) -> Option<EntityId> {
    canonical_id(intent_key.strip_prefix(INTENT_PREFIX)?)
}

/// The pair and part a part message's metadata names: exactly the two keys
/// the Coach writes, each once, in canonical form.
fn part_key(metadata: &rmpv::Value) -> Option<(EntityId, Part)> {
    let rmpv::Value::Map(entries) = metadata else {
        return None;
    };
    if entries.len() != 2 {
        return None;
    }
    Some((
        canonical_id(single_str(entries, META_PAIR)?)?,
        Part::named(single_str(entries, META_PART)?)?,
    ))
}

fn part_metadata(handle: EntityId, part: Part) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert(META_PAIR.to_owned(), handle.to_hex().into());
    metadata.insert(META_PART.to_owned(), part.name().into());
    serde_json::Value::Object(metadata)
}

/// The conversation `owner` and the Coach already share, where its training
/// offers are asked, if it was asked one yet.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn coach_owner_conversation_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &EntityId,
) -> Result<Option<EntityId>> {
    super::training_offer_ask::owner_conversation_in(vault, txn, owner)
}

/// The ask on `pair`'s reserved question TURN, its two answer TURNs as
/// context, that asks its owner which answers pass.
fn pair_ask_spec(pair: &OwnerPair) -> MemoryResult<TaskAskSpec> {
    let presentation = &pair.presentation;
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(presentation.question.turn));
    what.context_refs = vec![
        ConsultPayloadRef::Turn(presentation.shown_a.turn),
        ConsultPayloadRef::Turn(presentation.shown_b.turn),
    ];
    let mut options = BTreeMap::new();
    for choice in OwnerPairChoice::ALL {
        options.insert(
            TaskAskOptionId::new(choice.option())?,
            choice.label().to_owned(),
        );
    }
    what.options = options;
    let who = TaskAskTarget::Responder(TaskAssignee::Human {
        actor_ref: pair.owner,
    });
    let mut spec = TaskAskSpec::shorthand(Some(who), what, None, TaskAskDefault::Hold);
    spec.intent_key = format!("{INTENT_PREFIX}{}", pair.handle.to_hex());
    Ok(spec)
}

/// Asks `pair`'s owner about it as the Coach: witnesses each reserved part
/// that has not landed, with `texts`, then admits the ask with the pair's
/// route composed beside it. A retry replays the same ask. It never fails
/// its caller: a refusal (the Coach's reach revoked, a pair no longer open)
/// is logged quietly, any other failure is logged as a warning, and the
/// next pass asks again (FIX 3609).
pub(crate) fn ask_contribution_pair(vault: &Vault, pair: &OwnerPair, texts: &OwnerPairTexts) {
    let issued = vault
        .coach_authority()
        .map_err(MemoryError::from)
        .and_then(|issuer| {
            let memory = vault.memory(issuer.entity_ref(), issuer.actor_class());
            issue(vault, &memory, pair, texts)
        });
    match issued {
        Ok(()) => {}
        Err(error) if error.code == MEMORY_CODE_FORBIDDEN => {
            tracing::debug!(
                pair = %pair.handle.to_hex(),
                code = %error.code,
                "contribution pair ask refused"
            );
        }
        Err(error) => {
            tracing::warn!(
                pair = %pair.handle.to_hex(),
                code = %error.code,
                "contribution pair ask not issued"
            );
        }
    }
}

fn issue(
    vault: &Vault,
    issuer: &Memory<'_>,
    pair: &OwnerPair,
    texts: &OwnerPairTexts,
) -> MemoryResult<()> {
    let presentation = &pair.presentation;
    for part in Part::ALL {
        let (turn, message, _) = part.ids(pair);
        let landed = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            vault.get_entity_type_in_txn(&txn, &message)?.is_some()
        };
        if landed {
            continue;
        }
        issuer.witness(&WitnessTurn {
            conversation_ref: presentation.conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                // A new TURN needs one non-system speaker: the Coach speaks
                // to its owner as the companion (FIX 3609).
                author: WitnessAuthor::Companion,
                message_type: CONTRIBUTION_PAIR_QUESTION_TYPE.to_owned(),
                content: part.text(texts).to_owned(),
                parts: None,
                metadata: Some(part_metadata(pair.handle, part)),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: presentation.at,
            assertions: Default::default(),
        })?;
    }
    let spec = pair_ask_spec(pair)?;
    let route = ContributionPairRoute {
        handle: pair.handle,
        revision: spec.what.revision,
    };
    issuer.tasks_ask_composed(&spec, Some(AskEffect::ContributionPair(route)))?;
    Ok(())
}

/// Exact native pair copies in this snapshot, not authority to erase them.
/// The private pair permit owns this immutable MESSAGE type. Erase checks
/// its full envelope and reserved identities, not the now-settled ask's
/// admission state. A TURN with another child stays; its verified MESSAGE
/// can still leave.
pub(crate) fn contribution_pair_erase_targets_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pair: &OwnerPair,
) -> Result<Vec<(EntityId, Option<EntityId>)>> {
    use crate::EdgeKind;
    use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

    let coach = crate::store::base_agent::coach_actor_id()?;
    let conversation = pair.presentation.conversation;
    let sole_peer = |source: &EntityId,
                     direction: EdgeDirection,
                     kind: EdgeKind,
                     expected: EntityId|
     -> Result<bool> {
        let mut peers = vault.store.port_edge_peers(txn, source, direction, kind)?;
        if peers.next().transpose()? != Some(expected) {
            return Ok(false);
        }
        Ok(peers.next().transpose()?.is_none())
    };
    let mut targets = Vec::new();
    for part in Part::ALL {
        let (turn, message, digest) = part.ids(pair);
        let Some(record) = vault.store.port_entity_record(txn, &message)? else {
            continue;
        };
        if record.entity_type != ENTITY_TYPE_MESSAGE
            || crate::gate::validate_canonical_witness_message_body(&record.body).is_err()
        {
            continue;
        }
        let mut input = record.body.as_slice();
        let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut input) else {
            continue;
        };
        let field = |key: &str| {
            entries
                .iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .map(|(_, value)| value)
        };
        let Some(content) = single_str(&entries, "content") else {
            continue;
        };
        if single_str(&entries, "author") != Some("companion")
            || single_str(&entries, "type") != Some(CONTRIBUTION_PAIR_QUESTION_TYPE)
            || field("is_visible").and_then(rmpv::Value::as_bool) != Some(true)
            || field("order").and_then(rmpv::Value::as_u64) != Some(0)
            || field("parts").is_some()
            || field("metadata").and_then(part_key) != Some((pair.handle, part))
            || *blake3::hash(content.as_bytes()).as_bytes() != digest
            || !sole_peer(&message, EdgeDirection::Out, EdgeKind::PartOf, turn)?
            || !sole_peer(
                &message,
                EdgeDirection::Out,
                EdgeKind::BelongsTo,
                conversation,
            )?
            || !sole_peer(&message, EdgeDirection::Out, EdgeKind::AuthoredBy, coach)?
        {
            continue;
        }
        let mut erase_turn = None;
        if let Some(record) = vault.store.port_entity_record(txn, &turn)? {
            let mut input = record.body.as_slice();
            if record.entity_type == ENTITY_TYPE_TURN
                && let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut input)
                && input.is_empty()
                && entries.len() == 1
                && single_str(&entries, "speaker") == Some("assistant")
                && sole_peer(&turn, EdgeDirection::Out, EdgeKind::ChildOf, conversation)?
                && sole_peer(&turn, EdgeDirection::In, EdgeKind::PartOf, message)?
            {
                erase_turn = Some(turn);
            }
        }
        targets.push((message, erase_turn));
    }
    Ok(targets)
}

/// Whether the message at `ids` (its conversation, TURN and MESSAGE), with
/// `metadata` and `content`, is one reserved part of a pending pair no ask
/// carries yet, asked of a live owner: the reservation holds exactly these
/// ids and this text's digest. The witness door's check behind the Coach's
/// permit (`gate::coach_offer_question_permit_in_txn`).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn contribution_pair_question_permitted_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: (EntityId, EntityId, EntityId),
    metadata: &rmpv::Value,
    content: &str,
) -> Result<bool> {
    let Some((handle, part)) = part_key(metadata) else {
        return Ok(false);
    };
    let Some((_, pair)) = crate::code_run::owner_pair_in_txn(vault, txn, handle)? else {
        return Ok(false);
    };
    let (turn, message, digest) = part.ids(&pair);
    Ok(pair.route == OwnerPairRoute::Reserved
        && (pair.presentation.conversation, turn, message) == ids
        && *blake3::hash(content.as_bytes()).as_bytes() == digest
        && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &pair.owner)?)
}

/// Whether `input` asks exactly the pending pair its intent key names: of
/// the owner it asks, on its reserved question TURN with its two answer
/// TURNs as context, with no TASK or class, while no ask carries it and that
/// owner is live. The ask door's check behind the Coach's reach
/// (`gate::coach_offer_ask_ceiling_in_txn`).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn contribution_pair_ask_permitted_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &TaskAskSpec,
) -> Result<bool> {
    let Some(handle) = pair_handle(&input.intent_key) else {
        return Ok(false);
    };
    let Some((_, pair)) = crate::code_run::owner_pair_in_txn(vault, txn, handle)? else {
        return Ok(false);
    };
    let presentation = &pair.presentation;
    let asks_owner = matches!(
        &input.who,
        Some(TaskAskTarget::Responder(TaskAssignee::Human { actor_ref })) if *actor_ref == pair.owner
    );
    let context = [
        ConsultPayloadRef::Turn(presentation.shown_a.turn),
        ConsultPayloadRef::Turn(presentation.shown_b.turn),
    ];
    Ok(asks_owner
        && pair.route == OwnerPairRoute::Reserved
        && input.task_ref.is_none()
        && input.class.is_none()
        && input.what.reference == ConsultPayloadRef::Turn(presentation.question.turn)
        && input.what.context_refs == context
        && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &pair.owner)?)
}

/// Binds the pair `route` names to the ask `group`, in the ask's admission
/// or as the owner's approval releases a held ask: the revision it asks at
/// and the question digest it was admitted with. A pair no longer open
/// refuses, so its ask never goes out.
pub(super) fn route_pair_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    route: &ContributionPairRoute,
) -> MemoryResult<()> {
    let digest = ask_record::read_group(vault, txn, group)?
        .ok_or_else(ask_record::invalid)?
        .question_digest;
    let bound = crate::code_run::bind_owner_pair_ask_in_txn(
        vault,
        txn,
        route.handle,
        group,
        route.revision,
        digest,
    )?;
    if !bound {
        return Err(MemoryError::bad_request(
            "this contribution pair is no longer open",
        ));
    }
    Ok(())
}

fn owner_not_authenticated(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// Refuses a word on a contribution pair ask unless it is the asked owner's
/// own act: a Human word under the live proof of the owner the pair asks,
/// given on the node that admitted the ask, naming one of its options while
/// the pair waits on this ask. Any other ask passes untouched. Runs in
/// shared word admission, before the word is recorded, beside
/// `training_offer_ask::guard_word`.
///
/// # Errors
///
/// Storage errors, and every word it refuses.
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
    let Some(handle) = pair_handle(&group.requested.intent_key) else {
        return Ok(());
    };
    // The owner's own tap, never a word given for them or a soft confirm.
    if word.companion_for.is_some() || word.inform_for.is_some() || word.confirmation.is_some() {
        return Err(ask_record::invalid());
    }
    let Some((_, pair)) = crate::code_run::owner_pair_in_txn(vault, txn, handle)?
        .filter(|(_, pair)| matches!(pair.route, OwnerPairRoute::Asked { ask, .. } if ask == id))
    else {
        return Err(ask_record::invalid());
    };
    if word
        .option
        .as_ref()
        .and_then(|option| OwnerPairChoice::of_option(option.as_str()))
        .is_none()
    {
        return Err(ask_record::invalid());
    }
    // Only the admission node settles the ask, so a word anywhere else
    // could never settle under the proof that admitted it.
    if !ask_record::owns_revision(vault, txn, id, group)? {
        return Err(owner_not_authenticated(
            "a contribution pair answer is given on the node that admitted the ask",
        ));
    }
    let Some(owner) = owner else {
        return Err(owner_not_authenticated(
            "a contribution pair answer needs the owner's own authenticated word",
        ));
    };
    let proven = owner.revalidate_in_txn(vault, txn)?;
    if source != TaskAskSource::Human || proven != actor || proven != pair.owner {
        return Err(owner_not_authenticated(
            "a contribution pair answer is the asked owner's own word",
        ));
    }
    Ok(())
}

/// Whether settlement may cut a contribution pair ask for `reason` with
/// `decision` under `owner`. Its first word cuts it only under the live
/// proof of the owner it asked; without that proof the ask stays open, and
/// only its deadline or staleness closes it. Any other ask passes.
pub(super) fn may_cut(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
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
    let Some(handle) = pair_handle(&group.requested.intent_key) else {
        return Ok(true);
    };
    let Some((_, pair)) = crate::code_run::owner_pair_in_txn(vault, txn, handle)? else {
        return Ok(true);
    };
    let TaskAskDecision::First(answer) = decision else {
        return Ok(true);
    };
    match owner {
        Some(owner) => {
            let proven = owner.revalidate_in_txn(vault, txn)?;
            Ok(proven == answer.actor_ref && proven == pair.owner)
        }
        None => Ok(false),
    }
}

/// Settles the pair a contribution pair ask carries from `result`, in the
/// ask's settling transaction, the first cut's or a replay's. Any other ask
/// is untouched. The pair scores only on the owner's definitive word
/// ([`owner_word`]) under `owner`'s live proof; every other cut closes it
/// unscored ([`crate::code_run::settle_owner_pair_in_txn`]).
pub(super) fn resolve_answer_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    result: &TaskAskResult,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    let settlement = &result.settlement;
    let Some(handle) = pair_handle(&settlement.requested.intent_key) else {
        return Ok(());
    };
    let proven = match owner {
        Some(owner) => Some(owner.revalidate_in_txn(vault, txn)?),
        None => None,
    };
    let answer = OwnerPairAnswer {
        ask: settlement.group_ref,
        revision: settlement.revision,
        question_digest: settlement.question_digest,
        owner: proven,
        word: owner_word(result, proven),
    };
    crate::code_run::settle_owner_pair_in_txn(vault, txn, handle, &answer, settlement.at)
}

/// The owner's definitive word `result` cut on: a counted Human word
/// selected First, given by `proven` itself, with coverage met, no fallback,
/// cut neither at its deadline nor stale, naming one of the pair's options;
/// never a word given for the owner, an inform or a soft confirm. A word
/// that lands past the deadline closes the pair with no score (FIX 3609).
fn owner_word(
    result: &TaskAskResult,
    proven: Option<EntityId>,
) -> Option<(OwnerPairChoice, OwnerJudgment)> {
    let TaskAskDecision::First(answer) = &result.decision else {
        return None;
    };
    let settlement = &result.settlement;
    if !result.coverage.met
        || result.fallback.is_some()
        || matches!(
            settlement.reason,
            TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale
        )
        || proven != Some(answer.actor_ref)
    {
        return None;
    }
    let selected = result.evidence.iter().find(|entry| {
        entry.answer == *answer
            && entry.reason == TaskAskEvidenceReason::Counted
            && entry.source == TaskAskSource::Human
    })?;
    let word = &selected.word;
    if word.companion_for.is_some() || word.inform_for.is_some() || word.confirmation.is_some() {
        return None;
    }
    let choice = OwnerPairChoice::of_option(word.option.as_ref()?.as_str())?;
    Some((
        choice,
        OwnerJudgment {
            ask: settlement.group_ref,
            word: answer.word_ref,
            question_digest: settlement.question_digest,
            revision: settlement.revision,
            at: settlement.at,
        },
    ))
}

/// Cuts each still-open ask of `asks` Stale in `txn`, an erase's writer,
/// once the erase deleted the pending pair it carries: its words score
/// nothing and it stops waiting for its deadline. An ask settled already,
/// gone, or admitted by another node keeps to its own settlement or
/// deadline, and its pair is gone.
///
/// # Errors
///
/// Storage errors, or a cut that fails.
pub(crate) fn retire_contribution_pair_asks_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    asks: &[EntityId],
) -> Result<()> {
    if asks.is_empty() {
        return Ok(());
    }
    let now = vault.store.clock.now_recorded_at();
    for &ask in asks {
        if super::ask_settlement::read_result(vault, txn, ask)?.is_some() {
            continue;
        }
        let Some(group) = ask_record::read_group(vault, txn, ask)? else {
            continue;
        };
        if ask_record::owns_revision(vault, txn, ask, &group)? {
            super::ask_settlement::void_in(vault, txn, ask, now)?;
        }
    }
    Ok(())
}
