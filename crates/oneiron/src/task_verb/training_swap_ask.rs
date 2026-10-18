//! A Scored training run's result asked as a real `tasks.ask` (OF-577, FIX 857).
//!
//! A train yes runs the pack, then shows its result for a separate swap
//! choice: a trained model never deploys by itself. Once a run is scored and
//! its checks allow a proposal, the Coach asks each owner about it in its own
//! name: one System question in that owner's private conversation with the
//! Coach, carrying the result in brief, and an ask on its TURN that offers the
//! swap beside keep and holds by default. The ids are reserved once per run,
//! owner and result digest, so a retry lands the same question; a result
//! whose digest moved (another model took the role) is asked afresh, and the
//! questions about the older digest close.
//!
//! Only the asked owner's own word settles it, in the ask's settling commit:
//! a counted Human word under that owner's live proof, given on the node that
//! admitted the ask, while the run still waits at the expectation the
//! question froze. `approve_swap` binds the checkpoint through the training
//! pack's swap core in that commit; `keep` records the answer and binds
//! nothing. A deadline, default, abstention, or agent or companion word
//! approves nothing. Either answer cuts the run's other open asks Stale, and
//! an answered run is not asked again; the owner's direct swap door still
//! serves it. Embedder runs are not asked: their swap stages a re-embed
//! through a space move.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ask_record::{self, AskGroup};
use super::ask_types::{
    TaskAskDecision, TaskAskDefault, TaskAskEvidenceReason, TaskAskOptionId, TaskAskQuestion,
    TaskAskResult, TaskAskSettlementReason, TaskAskSource, TaskAskSpec, TaskAskTarget, TaskAskWord,
};
use super::training_offer_ask::{canonical_digest, canonical_id, single_str};
use super::{ConsultPayloadRef, TaskAssignee};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use crate::side_table::{self, Named, SideTable};
use crate::training_pack::{SwapChoice, SwapExpectation, TrainingRun, TrainingState};
use crate::{EntityId, Vault};

mod question;
use question::{candidate_in, swap_question_text};

/// Every training swap ask's intent key starts so:
/// `training_swap/<run hex>/<digest>/<owner hex>`.
const INTENT_PREFIX: &str = "training_swap/";
/// The message type of the witnessed question.
pub(crate) const SWAP_QUESTION_TYPE: &str = "training_swap_question";
/// The question message's metadata keys: the swap tuple. It locates the
/// reservation and proves nothing by itself.
const META_RUN: &str = "training_swap_run";
const META_DIGEST: &str = "training_swap_digest";
const META_OWNER: &str = "training_swap_owner";

/// What an owner's answer does to the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapAnswer {
    /// Bind the returned checkpoint to the run's role.
    Swap,
    /// Keep the current model.
    Keep,
}

/// The options every swap ask carries: stable id, the answer it settles and
/// its label.
const OPTIONS: [(&str, SwapAnswer, &str); 2] = [
    (
        "approve_swap",
        SwapAnswer::Swap,
        "Swap in the trained model",
    ),
    ("keep", SwapAnswer::Keep, "Keep the current model"),
];

/// Where one owner's question about one result stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapAskState {
    /// Reserved or asked, with no answer yet.
    Open,
    /// This owner's `approve_swap` bound the checkpoint.
    Swapped,
    /// This owner's `keep` kept the current model.
    Kept,
    /// Another answer, the owner's direct swap or a newer result closed it.
    Closed,
}

/// `(run, owner, result digest)`: one owner asked about one result.
type SwapAskKey = (EntityId, EntityId, String);

/// One owner's question about one result: ids and time reserved before the
/// witness, the expectation an approval binds against, the ask group once
/// admitted, and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwapAskRoute {
    run: EntityId,
    /// The question's fingerprint: the frozen expectation with the export
    /// checks the question shows, hashed (64 hex).
    digest: String,
    owner: EntityId,
    expected: SwapExpectation,
    conversation: EntityId,
    turn: EntityId,
    message: EntityId,
    at: u64,
    group: Option<EntityId>,
    state: SwapAskState,
}

/// The reserved ids and the text of a question that still waits.
pub(crate) struct PendingSwapQuestion {
    pub(crate) conversation: EntityId,
    pub(crate) turn: EntityId,
    pub(crate) message: EntityId,
    pub(crate) text: String,
}

/// One owner's question about a training run, as the owner door shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrainingSwapAskView {
    pub owner: EntityId,
    /// The result digest the question froze (64 hex).
    pub digest: String,
    pub expected: SwapExpectation,
    pub state: SwapAskState,
    /// The ask group, once admitted.
    pub group: Option<EntityId>,
    pub at: u64,
}

/// One result the Coach may ask about, with the owners not asked yet.
struct Unasked {
    run: TrainingRun,
    expected: SwapExpectation,
    digest: String,
    owners: Vec<EntityId>,
}

/// `(run, owner, digest)` → that owner's question about that result.
const ASKS: SideTable<SwapAskKey, SwapAskRoute, Named> =
    SideTable::new(&side_table::TASK_TRAINING_SWAP_ASK);

/// `ask group` → the reservation it carries.
const GROUPS: SideTable<EntityId, SwapAskKey, Named> =
    SideTable::new(&side_table::TASK_TRAINING_SWAP_ASK_GROUP);

fn owner_not_authenticated(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// Whether `intent_key` is a training swap ask's. The prefix admits nothing
/// by itself: a routed ask is one its group index names.
pub(crate) fn is_training_swap_ask_intent(intent_key: &str) -> bool {
    intent_key.starts_with(INTENT_PREFIX)
}

fn intent_key(key: &SwapAskKey) -> String {
    let (run, owner, digest) = key;
    format!(
        "{INTENT_PREFIX}{}/{digest}/{}",
        run.to_hex(),
        owner.to_hex()
    )
}

/// The swap tuple a training swap ask's intent key names, read whole and in
/// canonical form; `None` for any other key.
pub(crate) fn training_swap_ask_key(intent_key: &str) -> Option<SwapAskKey> {
    let mut parts = intent_key.strip_prefix(INTENT_PREFIX)?.split('/');
    let (Some(run), Some(digest), Some(owner), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some((
        canonical_id(run)?,
        canonical_id(owner)?,
        canonical_digest(digest)?,
    ))
}

/// The swap tuple a question message's metadata names: exactly the three
/// keys the Coach writes, each once, in canonical form.
pub(crate) fn swap_question_key(metadata: &rmpv::Value) -> Option<SwapAskKey> {
    let rmpv::Value::Map(entries) = metadata else {
        return None;
    };
    if entries.len() != 3 {
        return None;
    }
    Some((
        canonical_id(single_str(entries, META_RUN)?)?,
        canonical_id(single_str(entries, META_OWNER)?)?,
        canonical_digest(single_str(entries, META_DIGEST)?)?,
    ))
}

fn swap_question_metadata(key: &SwapAskKey) -> serde_json::Value {
    let (run, owner, digest) = key;
    let mut metadata = serde_json::Map::new();
    metadata.insert(META_RUN.to_owned(), run.to_hex().into());
    metadata.insert(META_DIGEST.to_owned(), digest.clone().into());
    metadata.insert(META_OWNER.to_owned(), owner.to_hex().into());
    serde_json::Value::Object(metadata)
}

/// The route and run `key` names while its question still waits: reserved
/// and open, asked of a live vault owner, the run still one the Coach may
/// ask about, at the expectation and digest the question froze.
fn pending_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &SwapAskKey,
) -> Result<Option<(SwapAskRoute, TrainingRun)>> {
    let Some(route) = ASKS.get(&vault.store, txn, key)? else {
        return Ok(None);
    };
    if route.state != SwapAskState::Open
        || !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &route.owner)?
    {
        return Ok(None);
    }
    let Some(run) = crate::training_pack::training_run_in(vault, txn, &route.run)? else {
        return Ok(None);
    };
    let manifest = crate::llm::manifest::read_manifest(&vault.store, txn)?;
    let live = candidate_in(vault, txn, &run, manifest.as_ref())?;
    Ok(live
        .filter(|(expected, digest)| {
            *expected == route.expected && *digest == route.digest && *digest == key.2
        })
        .map(|_| (route, run)))
}

/// The reserved ids and the text of the question `key` names while it still
/// waits; `None` otherwise.
/// # Errors
/// Storage errors, or a result that does not encode.
pub(crate) fn pending_swap_question_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &SwapAskKey,
) -> Result<Option<PendingSwapQuestion>> {
    let Some((route, run)) = pending_in(vault, txn, key)? else {
        return Ok(None);
    };
    Ok(Some(PendingSwapQuestion {
        conversation: route.conversation,
        turn: route.turn,
        message: route.message,
        text: swap_question_text(&run, &route.expected)?,
    }))
}

/// The answer `option` settles, when a swap ask offers it.
fn offered_answer(option: &TaskAskOptionId) -> Option<SwapAnswer> {
    OPTIONS
        .iter()
        .find(|(id, _, _)| *id == option.as_str())
        .map(|(_, answer, _)| *answer)
}

/// The ask on `turn` that asks the owner of `key` about its result.
fn swap_ask_spec(key: &SwapAskKey, turn: EntityId) -> MemoryResult<TaskAskSpec> {
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(turn));
    let mut options = BTreeMap::new();
    for (id, _, label) in OPTIONS {
        options.insert(TaskAskOptionId::new(id)?, label.to_owned());
    }
    what.options = options;
    let who = TaskAskTarget::Responder(TaskAssignee::Human { actor_ref: key.1 });
    let mut spec = TaskAskSpec::shorthand(Some(who), what, None, TaskAskDefault::Hold);
    spec.intent_key = intent_key(key);
    Ok(spec)
}

/// Closes every open question about `run` that `closes` picks, but the one
/// `except` carries: its route reads Closed, and its ask, when this node
/// admitted it and it is not settled, is cut Stale in `txn`, so its words
/// settle nothing and it stops waiting for its deadline. A held ask, or one
/// another node admitted, keeps to its deadline; its words are refused. A
/// Stale cut decides nothing, so it never swaps.
fn close_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    except: Option<&EntityId>,
    now: u64,
    closes: impl Fn(&SwapAskKey) -> bool,
) -> Result<()> {
    for (key, mut route) in ASKS.scan_from(&vault.store, txn, run.as_bytes())? {
        if route.state != SwapAskState::Open
            || !closes(&key)
            || except.is_some_and(|except| route.group == Some(*except))
        {
            continue;
        }
        route.state = SwapAskState::Closed;
        ASKS.put(&vault.store, txn, &key, &route)?;
        let Some(group) = route.group else {
            continue;
        };
        if super::ask_settlement::read_result(vault, txn, group)?.is_some() {
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

/// Cuts every other open question about `run` once an answer or the owner's
/// direct swap settled it. `except` is the ask whose own settlement carries
/// the answer.
/// # Errors
/// Storage errors, or a cut that fails.
pub(crate) fn void_training_swap_asks_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    except: Option<&EntityId>,
    now: u64,
) -> Result<()> {
    close_in(vault, txn, run, except, now, |_| true)
}

/// The reservation for `key`, its ids minted on first use, freezing
/// `expected`. A new digest closes the run's open questions about an older
/// one. An owner's later questions share the conversation of the first one
/// the Coach asked them, offer or swap.
fn reserve(
    vault: &Vault,
    key: &SwapAskKey,
    expected: &SwapExpectation,
    now: u64,
) -> Result<SwapAskRoute> {
    vault.with_write_txn_grouped(|txn| {
        if let Some(route) = ASKS.get(&vault.store, txn, key)? {
            return Ok(route);
        }
        let (run, owner, digest) = key;
        close_in(vault, txn, run, None, now, |asked| asked.2 != *digest)?;
        let conversation = match ASKS
            .scan(&vault.store, txn)?
            .into_iter()
            .find(|(_, route)| route.owner == *owner)
        {
            Some((_, route)) => route.conversation,
            None => match super::training_offer_ask::owner_conversation_in(vault, txn, owner)? {
                Some(conversation) => conversation,
                None => vault.store.clock.entity_id()?,
            },
        };
        let route = SwapAskRoute {
            run: *run,
            digest: digest.clone(),
            owner: *owner,
            expected: expected.clone(),
            conversation,
            turn: vault.store.clock.entity_id()?,
            message: vault.store.clock.entity_id()?,
            at: now,
            group: None,
            state: SwapAskState::Open,
        };
        ASKS.put(&vault.store, txn, key, &route)?;
        Ok(route)
    })
}

/// Binds `group` to the reservation `key` and indexes it, once.
fn bind_group_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &SwapAskKey,
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

/// Each result the Coach may ask about, with the owners not asked about it
/// yet. A run an owner answered is not asked again.
fn unasked(vault: &Vault) -> Result<Vec<Unasked>> {
    let txn = vault.store.env.read_txn()?;
    let runs = crate::training_pack::training_runs_in(vault, &txn)?;
    if !runs.iter().any(|run| run.state == TrainingState::Scored) {
        return Ok(Vec::new());
    }
    let manifest = crate::llm::manifest::read_manifest(&vault.store, &txn)?;
    let owners = crate::policy_model::owners_in_txn(vault, &txn)?;
    let mut unasked = Vec::new();
    for run in runs {
        let Some((expected, digest)) = candidate_in(vault, &txn, &run, manifest.as_ref())? else {
            continue;
        };
        let routes = ASKS.scan_from(&vault.store, &txn, run.id.as_bytes())?;
        if routes
            .iter()
            .any(|(_, route)| matches!(route.state, SwapAskState::Swapped | SwapAskState::Kept))
        {
            continue;
        }
        let left = owners
            .iter()
            .copied()
            .filter(|owner| {
                !routes.iter().any(|((_, asked, at), route)| {
                    asked == owner && *at == digest && route.group.is_some()
                })
            })
            .collect::<Vec<_>>();
        if !left.is_empty() {
            unasked.push(Unasked {
                run,
                expected,
                digest,
                owners: left,
            });
        }
    }
    Ok(unasked)
}

/// Asks `owner` about `row` as `issuer`: reserves the question, witnesses it
/// unless it already landed, and admits the ask with its group bound in the
/// admission's commit. Returns whether this call admitted a new ask.
fn issue_one(
    vault: &Vault,
    issuer: &Memory<'_>,
    row: &Unasked,
    owner: EntityId,
    now: u64,
) -> MemoryResult<bool> {
    let key = (row.run.id, owner, row.digest.clone());
    let route = reserve(vault, &key, &row.expected, now)?;
    if route.group.is_some() || route.state != SwapAskState::Open {
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
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(route.message.to_hex()),
                author: WitnessAuthor::System,
                message_type: SWAP_QUESTION_TYPE.to_owned(),
                content: swap_question_text(&row.run, &route.expected)?,
                metadata: Some(swap_question_metadata(&key)),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: route.at,
            assertions: Default::default(),
        })?;
    }
    let spec = swap_ask_spec(&key, route.turn)?;
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

/// Asks every owner about every Scored result they were not asked about yet,
/// as the Coach. Returns how many asks this pass admitted, and never fails
/// its caller: a refusal (the Coach's reach revoked) is logged quietly and
/// the next tuple goes on. A run that raises no ask still waits for the
/// owner's direct swap door.
pub(crate) fn issue_training_swap_asks(vault: &Vault, now: u64) -> usize {
    let unasked = match unasked(vault) {
        Ok(unasked) => unasked,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "training swap asks not read");
            return 0;
        }
    };
    if unasked.is_empty() {
        return 0;
    }
    let issuer = match vault.coach_authority() {
        Ok(issuer) => issuer,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "training swap ask issuer not resolved");
            return 0;
        }
    };
    let memory = vault.memory(issuer.entity_ref(), issuer.actor_class());
    let mut issued = 0;
    for row in &unasked {
        for owner in &row.owners {
            match issue_one(vault, &memory, row, *owner, now) {
                Ok(true) => issued += 1,
                Ok(false) => {}
                Err(error) if error.code == MEMORY_CODE_FORBIDDEN => {
                    tracing::debug!(
                        run = %row.run.id.to_hex(),
                        code = %error.code,
                        "training swap ask refused"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        run = %row.run.id.to_hex(),
                        code = %error.code,
                        "training swap ask not issued"
                    );
                }
            }
        }
    }
    issued
}

/// The reservation an ask group carries, with its key, when the Coach's
/// issuance bound it; `None` for every other ask. A bound group whose
/// reservation does not name it back fails closed.
fn routed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Option<(SwapAskKey, SwapAskRoute)>> {
    if !is_training_swap_ask_intent(&group.requested.intent_key) {
        return Ok(None);
    }
    let Some(key) = GROUPS.get(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let route = ASKS
        .get(&vault.store, txn, &key)?
        .filter(|route| route.group == Some(id) && intent_key(&key) == group.requested.intent_key)
        .ok_or_else(ask_record::invalid)?;
    Ok(Some((key, route)))
}

/// Refuses a word on a training swap ask unless it is the asked owner's own
/// act on a question that still waits; any other ask passes untouched. Runs
/// in shared word admission, before the word is recorded.
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
    let Some((key, route)) = routed_in(vault, txn, id, group)? else {
        return Ok(());
    };
    // The owner's own tap, never a word given for them or a soft confirm.
    if word.companion_for.is_some() || word.inform_for.is_some() || word.confirmation.is_some() {
        return Err(ask_record::invalid());
    }
    // A definitive answer names one option the ask offered, while the run
    // still waits at the expectation the question froze.
    if word.option.as_ref().and_then(offered_answer).is_none()
        || pending_in(vault, txn, &key)?.is_none()
    {
        return Err(ask_record::invalid());
    }
    // Only the admission node settles the ask, so a word anywhere else
    // could never settle under the proof that admitted it.
    if !ask_record::owns_revision(vault, txn, id, group)? {
        return Err(owner_not_authenticated(
            "a training swap answer is given on the node that admitted the ask",
        ));
    }
    let Some(owner) = owner else {
        return Err(owner_not_authenticated(
            "a training swap answer needs the owner's own authenticated word",
        ));
    };
    let proven = owner.revalidate_in_txn(vault, txn)?;
    if source != TaskAskSource::Human || proven != actor || proven != route.owner {
        return Err(owner_not_authenticated(
            "a training swap answer is the asked owner's own word",
        ));
    }
    Ok(())
}

/// Whether settlement may cut the ask `id` for `reason` with `decision`
/// under `owner`. A training swap ask's first word settles the run only
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
    let Some((_, route)) = routed_in(vault, txn, id, group)? else {
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

/// Settles the run from the word `result` selected, in the ask's settling
/// transaction, before the settlement is stored.
///
/// It acts only on a definitive cut of a training swap ask: a counted Human
/// word selected First, coverage met, no fallback, not stale, live owner
/// proof naming that word's actor and the asked owner, and the run still
/// waiting at the frozen expectation. `approve_swap` binds the checkpoint
/// against that expectation; `keep` binds nothing. Either cuts the run's
/// other open asks Stale. Every other case is a no-op, never an approval.
pub(super) fn resolve_answer_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: &AskGroup,
    result: &TaskAskResult,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    let id = result.settlement.group_ref;
    let Some((key, route)) = routed_in(vault, txn, id, group)? else {
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
    let Some(choice) = selected.word.option.as_ref().and_then(offered_answer) else {
        return Ok(());
    };
    if pending_in(vault, txn, &key)?.is_none() {
        return Ok(());
    }
    let state = match choice {
        SwapAnswer::Swap => {
            vault.approve_training_role_swap_in_txn(
                txn,
                owner,
                &route.run,
                SwapChoice::Evaluated,
                None,
                Some(&route.expected),
            )?;
            SwapAskState::Swapped
        }
        SwapAnswer::Keep => SwapAskState::Kept,
    };
    let run = route.run;
    ASKS.put(&vault.store, txn, &key, &SwapAskRoute { state, ..route })?;
    void_training_swap_asks_in(vault, txn, &run, Some(&id), result.settlement.at)
}

/// Every question the Coach reserved about `run`'s results, by owner and
/// digest.
/// # Errors
/// Storage errors.
pub fn training_swap_asks(vault: &Vault, run: &EntityId) -> Result<Vec<TrainingSwapAskView>> {
    let txn = vault.store.env.read_txn()?;
    Ok(ASKS
        .scan_from(&vault.store, &txn, run.as_bytes())?
        .into_iter()
        .map(|(_, route)| TrainingSwapAskView {
            owner: route.owner,
            digest: route.digest,
            expected: route.expected,
            state: route.state,
            group: route.group,
            at: route.at,
        })
        .collect())
}
