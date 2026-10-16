//! The room join and consent doors (OF-531).
//!
//! `rooms.join` files a join and decides it in the writer: the caller is the
//! subject's own actor or its principal. `rooms.consent` records one party's
//! answer, from that party only, and decides again. A Ready decision commits
//! the participation and its receipt in one transaction; a Hold persists the
//! intent and the parties it waits on, with no seat, launch or spend hold; a
//! refusal is typed and final. Membership is never answered here: it is read
//! live from the vault's roster, which only the membership doors change.

use serde::{Deserialize, Serialize};

use super::join_consent::{
    ConsentNeed, ConsentPart, ConsentSet, ConsentState, JoinDecision, JoinRequest, JoinSubject,
    RequiredParty, SpendConsent, agent_person_in_txn, decide_with_in_txn, home_room_seats_in_txn,
    person_of_actor_in_txn,
};
use super::join_receipt::{
    JOINS, JoinFiling, JoinParticipation, JoinReceipt, JoinReceiptRef, READY, RecordedAnswer,
    intent_digest, is_join_ref, join_ref, ready_key,
};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState, payer_binds_in_txn};
use crate::conversation::{HistoryChoice, room_host_in_txn};
use crate::error::{ClaimError, Error, Result};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

/// One party's answer to a join that waits on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentAnswer {
    pub join_ref: String,
    pub part: ConsentPart,
    pub grant: bool,
    /// For a payer's yes: the scope it funds, opened with the payer's
    /// consent on its root.
    #[serde(default)]
    pub spend_scope: Option<SpendScopeId>,
}

/// A join's decision as its receipt holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinDecisionView {
    pub state: JoinDecision,
    pub consents: ConsentSet,
    pub participation: Option<JoinParticipation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinOutcome {
    pub join_ref: String,
    pub decision: JoinDecisionView,
    /// The receipt a Ready join committed: the evidence later work in the
    /// room re-proves. `None` while the join holds or after it was refused.
    pub receipt_ref: Option<String>,
}

impl JoinOutcome {
    fn of(receipt: &JoinReceipt) -> Self {
        Self {
            join_ref: receipt.join_ref.clone(),
            decision: JoinDecisionView {
                state: receipt.decision.clone(),
                consents: receipt.consents.clone(),
                participation: receipt.participation,
            },
            receipt_ref: receipt.participation.map(|_| {
                JoinReceiptRef::for_join(&receipt.join_ref)
                    .as_str()
                    .to_owned()
            }),
        }
    }
}

impl Memory<'_> {
    /// Files and decides a join for the bound actor. See [`rooms_join_in_txn`].
    pub fn rooms_join(&self, request: &JoinRequest) -> MemoryResult<JoinOutcome> {
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            Ok(rooms_join_in_txn(vault, txn, request, caller, now)?)
        })
    }

    /// Records one party's answer to a join that waits on it, from that party
    /// only, and decides again. Membership is never answered here.
    pub fn rooms_consent(&self, answer: &ConsentAnswer) -> MemoryResult<JoinOutcome> {
        if answer.part == ConsentPart::Membership {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "membership is read live from the vault's roster; a room join never grants it",
                &[
                    "A vault Owner or Admin adds the person, or grants guest access, through the membership doors.",
                    "Then file the join again with the same intent_key: it decides again against the roster.",
                ],
            ));
        }
        if !is_join_ref(&answer.join_ref) {
            return Err(MemoryError::bad_request(
                "join_ref is the 64-hex reference rooms.join returned",
            ));
        }
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            if !JOINS.contains(&vault.store, txn, &answer.join_ref)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_NOT_FOUND,
                    "no join is filed under this join_ref",
                    &["File the join with rooms.join first."],
                ));
            }
            Ok(rooms_consent_in_txn(vault, txn, answer, caller, now)?)
        })
    }
}

/// Files and decides `request` in the caller's write transaction, so a write
/// that joins (a DAG append, an offer's settlement) commits with its join.
///
/// `caller` must be a live, bound actor that is the subject's own actor or
/// its principal: a companion's person, an agent's person, or a live owner
/// for the vault's own agent. A payer filing under a scope it funds gives
/// that payer's yes. The same intent replays: Ready and refused joins return
/// as stored, a held one decides again against live facts. The same intent
/// key with another request refuses.
pub fn rooms_join_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &JoinRequest,
    caller: WriteActor,
    now: u64,
) -> Result<JoinOutcome> {
    if request.intent_key.is_empty()
        || request.intent_key.len() > 128
        || !request
            .intent_key
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(Error::InvalidConfig(
            "a join's intent_key is 1..=128 printable bytes".into(),
        ));
    }
    vault.verify_write_actor_in_txn(txn, &caller)?;
    let principal = caller_stands_for_in_txn(vault, txn, caller, &request.subject, now)?;
    let join_ref = join_ref(request)?;
    let intent_digest = intent_digest(request)?;
    let mut filing = match JOINS.get(&vault.store, txn, &join_ref)? {
        Some(stored) if stored.intent_digest != intent_digest => {
            return Err(Error::InvalidConfig(
                "this intent_key already names a different join".into(),
            ));
        }
        Some(stored) if stored.is_settled() => return Ok(JoinOutcome::of(&stored)),
        Some(stored) => stored.into_filing(),
        None => JoinFiling {
            join_ref,
            intent_digest,
            request: request.clone(),
            filed_by: caller.entity_ref(),
            principal,
            answers: Vec::new(),
            filed_at: now,
        },
    };
    // A filer naming a scope it funds is that payer's own yes.
    if request.paid
        && let Some(scope) = &request.spend_scope
        && !filing
            .answers
            .iter()
            .any(|answer| answer.part == ConsentPart::Spend)
        && let Some((_, root)) = AgentDispatcher::new(vault).scope_with_root_in_txn(txn, scope)?
        && let Some(payer) = root.payer
        && person_of_actor_in_txn(vault, txn, caller.entity_ref(), now)? == Some(payer.party)
    {
        filing.answers.push(RecordedAnswer {
            part: ConsentPart::Spend,
            by: payer.party,
            actor: caller.entity_ref(),
            grant: true,
            spend_scope: Some(scope.clone()),
            answer_ref: answer_ref(vault)?,
            at: now,
        });
    }
    let receipt = settle_in_txn(vault, txn, filing, caller, now)?;
    Ok(JoinOutcome::of(&receipt))
}

/// Records `answer` on a filed join, from the party its part names, and
/// decides again in the caller's write transaction. A settled join replays
/// as stored.
pub fn rooms_consent_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    answer: &ConsentAnswer,
    caller: WriteActor,
    now: u64,
) -> Result<JoinOutcome> {
    vault.verify_write_actor_in_txn(txn, &caller)?;
    let receipt = JOINS
        .get(&vault.store, txn, &answer.join_ref)?
        .ok_or(Error::EntityNotFound)?;
    if receipt.is_settled() {
        return Ok(JoinOutcome::of(&receipt));
    }
    let (by, spend_scope) = match answer.part {
        ConsentPart::Membership => {
            return Err(refused(
                "membership is read live from the vault's roster; a room join never grants it",
            ));
        }
        ConsentPart::Admission => {
            if caller.actor_class() != EdgeActorClass::Human
                || room_host_in_txn(vault, txn, receipt.request.room, caller)?.is_none()
            {
                return Err(refused(
                    "only the room's owner or a delegated host answers its admission",
                ));
            }
            (caller.entity_ref(), None)
        }
        ConsentPart::Spend => {
            let person = person_of_actor_in_txn(vault, txn, caller.entity_ref(), now)?
                .ok_or_else(|| refused("a payer answers as its own PERSON"))?;
            if !receipt.request.paid {
                return Err(Error::InvalidConfig(
                    "this join launches no paid work, so it has no payer to answer".into(),
                ));
            }
            payer_answer_in_txn(vault, txn, &receipt.consents, answer, person)?
        }
    };
    let mut filing = receipt.into_filing();
    filing.answers.push(RecordedAnswer {
        part: answer.part,
        by,
        actor: caller.entity_ref(),
        grant: answer.grant,
        spend_scope,
        answer_ref: answer_ref(vault)?,
        at: now,
    });
    let receipt = settle_in_txn(vault, txn, filing, caller, now)?;
    Ok(JoinOutcome::of(&receipt))
}

/// A payer's yes names an open scope whose root `person` funds; its no
/// comes only from the payer the join names.
fn payer_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    consents: &ConsentSet,
    answer: &ConsentAnswer,
    person: EntityId,
) -> Result<(EntityId, Option<SpendScopeId>)> {
    if !answer.grant {
        let named = match &consents.spend {
            ConsentState::Missing(ConsentNeed {
                party: RequiredParty::Payer(payer),
                ..
            })
            | ConsentState::Granted(SpendConsent::Paid { payer, .. }) => Some(*payer),
            _ => None,
        };
        if named != Some(person) {
            return Err(refused("only the payer this join names may decline it"));
        }
        return Ok((person, None));
    }
    let scope = answer.spend_scope.clone().ok_or_else(|| {
        Error::InvalidConfig("a payer's yes names the spend scope it funds".into())
    })?;
    let (row, root) = AgentDispatcher::new(vault)
        .scope_with_root_in_txn(txn, &scope)?
        .ok_or_else(|| Error::InvalidConfig("no such spend scope".into()))?;
    let funds = match &root.payer {
        Some(payer) => payer.party == person && payer_binds_in_txn(vault, txn, payer)?,
        None => false,
    };
    if !funds {
        return Err(refused("the scope is not one this payer funds"));
    }
    if row.state != SpendState::Open || root.state != SpendState::Open {
        return Err(Error::InvalidConfig("the spend scope is closed".into()));
    }
    Ok((person, Some(scope)))
}

/// Decides a filing and writes its receipt. Ready commits the participation
/// and indexes the receipt for its exact room or thread, in this transaction.
fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    filing: JoinFiling,
    actor: WriteActor,
    now: u64,
) -> Result<JoinReceipt> {
    let (decision, consents) = decide_with_in_txn(
        vault,
        txn,
        &filing.request,
        filing.principal,
        &filing.answers,
        now,
    )?;
    let participation = if decision == JoinDecision::Ready {
        let request = &filing.request;
        READY.put(
            &vault.store,
            txn,
            &ready_key(request.room, &request.subject, request.branch),
            &filing.join_ref,
        )?;
        Some(participate_in_txn(vault, txn, request, actor, now)?)
    } else {
        None
    };
    let receipt = JoinReceipt::decided(filing, consents, decision, participation, now);
    JOINS.put(&vault.store, txn, &receipt.join_ref, &receipt)?;
    Ok(receipt)
}

/// The participation a Ready join commits. Only a person joining an ordinary
/// room itself takes a ledger seat; everyone else's evidence is the receipt.
fn participate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &JoinRequest,
    actor: WriteActor,
    now: u64,
) -> Result<JoinParticipation> {
    let JoinSubject::Person(person) = request.subject else {
        return Ok(JoinParticipation::AgentReceipt);
    };
    if request.branch.is_some() {
        return Ok(JoinParticipation::BranchReceipt);
    }
    // Only the project's board seats a home room's members.
    if home_room_seats_in_txn(vault, txn, request.room)?.is_some() {
        return Ok(JoinParticipation::HomeRoomReceipt);
    }
    if vault.members_in_txn(txn, request.room)?.contains(&person) {
        return Ok(JoinParticipation::AlreadySeated);
    }
    vault.join_member_in_txn(
        txn,
        request.room,
        person,
        actor,
        now,
        HistoryChoice::Inherit,
    )?;
    Ok(JoinParticipation::LedgerSeat)
}

/// Whom `caller` may file a join for: the subject itself, or its principal.
/// For the vault's own agent, returns the live owner filing for it.
fn caller_stands_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
    subject: &JoinSubject,
    at: u64,
) -> Result<Option<EntityId>> {
    let me = caller.entity_ref();
    let mine = person_of_actor_in_txn(vault, txn, me, at)?;
    let speaks_for = |person: EntityId| me == person || mine == Some(person);
    let person = match *subject {
        JoinSubject::Person(person) => person,
        JoinSubject::Agent(agent) if agent == me => return Ok(None),
        JoinSubject::Agent(agent) => match agent_person_in_txn(vault, txn, agent, at)? {
            Some(person) => person,
            // The vault's own agent: a live owner files for it.
            None => {
                return match mine {
                    Some(owner)
                        if crate::policy_model::owners_in_txn(vault, txn)?.contains(&owner) =>
                    {
                        Ok(Some(owner))
                    }
                    _ => Err(refused("only the agent or a live owner files its join")),
                };
            }
        },
    };
    if speaks_for(person)
        || super::codec::companion_principal_in_txn(vault, txn, person)?.is_some_and(speaks_for)
    {
        return Ok(None);
    }
    Err(refused(
        "a join is filed by its subject or the subject's principal",
    ))
}

fn answer_ref(vault: &Vault) -> Result<String> {
    Ok(format!(
        "rooms.consent:{}",
        vault.store.clock.entity_id()?.to_hex()
    ))
}

fn refused(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}
