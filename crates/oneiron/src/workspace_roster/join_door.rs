//! The room join and consent doors (OF-531).
//!
//! `rooms.join` files a join and decides it in the writer: the caller is the
//! subject's own actor or its principal, and its filing is the subject's own
//! yes. A board writer's roster write files an invitation instead (OF-417):
//! the same join for a person it seats and cannot speak for, waiting on her
//! yes. `rooms.consent` records one party's answer, from that party only, and
//! decides again; the invitee accepts or declines there, as the subject. A Ready decision commits
//! the participation and its receipt in one transaction; a Hold persists the
//! intent and the parties it waits on, with no seat, launch or spend hold; a
//! refusal is typed and final. Membership is never answered here: it is read
//! live from the vault's roster, which only the membership doors change.

use serde::{Deserialize, Serialize};

use super::join_consent::{
    AdmissionBasis, AdmissionConsent, ConsentNeed, ConsentPart, ConsentSet, ConsentState,
    JoinDecision, JoinRequest, JoinSubject, RequiredParty, SpendConsent, agent_person_in_txn,
    decide_with_in_txn, home_room_seats_in_txn, person_of_actor_in_txn,
};
use super::join_receipt::{
    JOINS, JoinFiling, JoinParticipation, JoinReceipt, JoinReceiptRef, READY, RecordedAnswer,
    intent_digest, is_join_ref, join_ref, ready_key,
};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState, payer_binds_in_txn};
use crate::conversation::{
    ContainerAttendee, ContainerAttendeeEvent, HistoryChoice, room_host_in_txn,
};
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
    pub(super) fn of(receipt: &JoinReceipt) -> Self {
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
        self.rooms_join_entering(request, HistoryChoice::Inherit)
    }

    /// [`Self::rooms_join`] naming the history a person's first entry into
    /// an ordinary room sees until the owner's P5 answer moves it (OF-365).
    /// Any other join refuses a choice other than the room's own rule.
    pub fn rooms_join_entering(
        &self,
        request: &JoinRequest,
        history: HistoryChoice,
    ) -> MemoryResult<JoinOutcome> {
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let principal = caller_stands_for_in_txn(vault, txn, caller, &request.subject, now)?;
            Ok(file_join_in_txn(
                vault, txn, request, history, caller, now, principal, true,
            )?)
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
/// for the vault's own agent. Its filing is the subject's own yes. A payer
/// filing under a scope it funds gives that payer's yes. The same intent
/// replays: Ready and refused joins return as stored, a held one decides
/// again against live facts. The same intent key with another request
/// refuses.
pub fn rooms_join_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &JoinRequest,
    caller: WriteActor,
    now: u64,
) -> Result<JoinOutcome> {
    vault.verify_write_actor_in_txn(txn, &caller)?;
    let principal = caller_stands_for_in_txn(vault, txn, caller, &request.subject, now)?;
    file_join_in_txn(
        vault,
        txn,
        request,
        HistoryChoice::Inherit,
        caller,
        now,
        principal,
        true,
    )
}

/// Files a board writer's invitation (OF-417): an unpaid room join for a
/// person its roster write newly seats and `caller` cannot speak for. It
/// carries no subject's yes, so it holds until the person, or her principal,
/// answers the subject part through `rooms.consent`; a no refuses it for its
/// intent. Only the installed roster adapter files one, never the SDK.
pub(super) fn rooms_invite_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &JoinRequest,
    caller: WriteActor,
    now: u64,
) -> Result<JoinOutcome> {
    vault.verify_write_actor_in_txn(txn, &caller)?;
    if !matches!(request.subject, JoinSubject::Person(_))
        || request.branch.is_some()
        || request.paid
        || request.spend_scope.is_some()
    {
        return Err(Error::InvalidConfig(
            "a roster invitation is an unpaid person's room join".into(),
        ));
    }
    file_join_in_txn(
        vault,
        txn,
        request,
        HistoryChoice::Inherit,
        caller,
        now,
        None,
        false,
    )
}

/// Files and decides `request` for a `caller` its door already verified.
/// `principal` is the owner a vault's own agent stands through; `accepts`
/// when `caller` stands for the subject, so its filing is the subject's yes,
/// and false for an invitation, which waits on that yes.
#[allow(clippy::too_many_arguments)]
fn file_join_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &JoinRequest,
    history: HistoryChoice,
    caller: WriteActor,
    now: u64,
    principal: Option<EntityId>,
    accepts: bool,
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
    if history != HistoryChoice::Inherit && !first_entry_in_txn(vault, txn, request)? {
        return Err(Error::InvalidConfig(
            "only a person's first entry into an ordinary room chooses its history; this join keeps the room's own rule".into(),
        ));
    }
    let join_ref = join_ref(request)?;
    let intent_digest = intent_digest(request)?;
    let mut filing = match JOINS.get(&vault.store, txn, &join_ref)? {
        Some(stored) if stored.intent_digest != intent_digest || stored.history != history => {
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
            history,
            filed_by: caller.entity_ref(),
            principal,
            answers: Vec::new(),
            filed_at: now,
        },
    };
    // A filer that stands for the subject is the subject's own yes.
    if accepts
        && !filing
            .answers
            .iter()
            .any(|answer| answer.part == ConsentPart::Subject)
    {
        filing.answers.push(RecordedAnswer {
            part: ConsentPart::Subject,
            by: request.subject.id(),
            actor: caller.entity_ref(),
            grant: true,
            spend_scope: None,
            answer_ref: answer_ref(vault)?,
            at: now,
        });
    }
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
        // The invitee accepts or declines as the subject, or through her
        // principal, proved again here.
        ConsentPart::Subject => {
            caller_stands_for_in_txn(vault, txn, caller, &receipt.request.subject, now)?;
            (receipt.request.subject.id(), None)
        }
        ConsentPart::Membership => {
            return Err(refused(
                "membership is read live from the vault's roster; a room join never grants it",
            ));
        }
        ConsentPart::Admission => {
            require_admission_party_in_txn(vault, txn, receipt.request.room, caller)?;
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
/// A person's own Ready join of a room brings her companions with her, when
/// `actor` speaks for her (OF-417): each is filed through this same door.
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
        Some(participate_in_txn(
            vault,
            txn,
            request,
            filing.history,
            &consents,
            actor,
            now,
        )?)
    } else {
        None
    };
    let receipt = JoinReceipt::decided(filing, consents, decision, participation, now);
    JOINS.put(&vault.store, txn, &receipt.join_ref, &receipt)?;
    if participation.is_some()
        && receipt.request.branch.is_none()
        && let JoinSubject::Person(principal) = receipt.request.subject
    {
        super::workplace_join::file_companion_joins_in_txn(
            vault,
            txn,
            receipt.request.room,
            principal,
            actor,
            now,
        )?;
    }
    Ok(receipt)
}

/// The participation a Ready join commits. Only a person joining an ordinary
/// room on standing of her own takes a ledger seat; everyone else's evidence
/// is the receipt.
///
/// A person's first entry also records its P5 entry fact (ILDF2 P5, OF-365),
/// the one the owner's clearance answer names (`/v1/owner/disclosure/entry/*`),
/// and sees `history` until that answer moves it. A rejoin keeps the room's
/// own rule.
fn participate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &JoinRequest,
    history: HistoryChoice,
    consents: &ConsentSet,
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
    if matches!(
        consents.admission,
        ConsentState::Granted(AdmissionConsent {
            basis: AdmissionBasis::ThroughPrincipal { .. },
            ..
        })
    ) {
        return Ok(JoinParticipation::PrincipalReceipt);
    }
    let first = first_entry_in_txn(vault, txn, request)?;
    vault.join_member_in_txn(
        txn,
        request.room,
        person,
        actor,
        now,
        if first {
            history
        } else {
            HistoryChoice::Inherit
        },
    )?;
    if first {
        crate::task_verb::admit_attendee_entry_in_txn(
            vault,
            txn,
            actor.entity_ref(),
            &ContainerAttendeeEvent {
                container: request.room,
                attendee: ContainerAttendee::Person(person),
                roster_revision: now.max(1),
                trigger_turn: None,
                candidates: Vec::new(),
                until: now,
                history,
            },
        )?;
    }
    Ok(JoinParticipation::LedgerSeat)
}

/// Whether `request` is a person's first entry into an ordinary room: no
/// thread, no project room, and never yet in the room's ledger.
fn first_entry_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
) -> Result<bool> {
    let JoinSubject::Person(person) = request.subject else {
        return Ok(false);
    };
    Ok(request.branch.is_none()
        && super::project_room_audience_in(vault, txn, request.room, &[])?.is_none()
        && !vault.ever_members_in_txn(txn, request.room)?.contains(&person))
}

/// Whom `caller` may file a join for: the subject itself, or its principal.
/// For the vault's own agent, returns the live owner filing for it.
pub(super) fn caller_stands_for_in_txn(
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

/// Refuses `caller` unless it answers `room`'s admission: a human who owns
/// the room or holds its delegated host role, read live.
pub(super) fn require_admission_party_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
) -> Result<()> {
    if caller.actor_class() != EdgeActorClass::Human
        || room_host_in_txn(vault, txn, room, caller)?.is_none()
    {
        return Err(refused(
            "only the room's owner or a delegated host answers its admission",
        ));
    }
    Ok(())
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
