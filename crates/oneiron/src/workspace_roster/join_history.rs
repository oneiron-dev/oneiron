//! A settled join of an erased party, as stored (FIX 4228): history only.
//!
//! A settled join whose subject, or a party its consents name by id, was
//! erased keeps its ref, its intent digest, its request's place and key, its
//! decision and its times, so every row that names its ref still finds it.
//! Each id it named reads as a [`RosterActor`]: no one where the actor was
//! erased. It sits in the join table under its own shape, which no live
//! reader decodes, so nothing decides, replays, proves or indexes it again.

use serde::{Deserialize, Serialize};

use super::join_consent::{
    AdmissionBasis, ConsentDenial, ConsentNeed, ConsentPart, ConsentState, JoinDecision,
    JoinRefusal, MembershipConsent, RequiredParty, SpendConsent,
};
use super::join_receipt::{JoinParticipation, JoinReceipt, RecordedAnswer, RosterActor};
use crate::EntityId;
use crate::agent_dispatch::SpendScopeId;
use crate::conversation::HistoryChoice;
use crate::error::{Error, Result};
use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;

/// What an actor's erase does with a settled join, or a settled offer card,
/// that names it by an id where only a live party can stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterBindingErase {
    /// The row stays as inert history: its ref and digests as filed, each
    /// erased party naming no one, and nothing deciding, replaying, proving
    /// or indexing it again.
    PreserveDigestInertHistory,
    /// The row goes.
    Delete,
}

/// A settled join's ref keys its offer card, its participation facts and
/// the receipts later work froze, so the join of an erased party stays as
/// history rather than going (FIX 4228; a call).
pub const ACTOR_ERASE_JOIN_BINDING: RosterBindingErase =
    RosterBindingErase::PreserveDigestInertHistory;

/// Every join row as stored: a live receipt, or one that turned history.
/// Key: its join ref.
pub(super) const JOIN_ROWS: SideTable<String, JoinRow, LegacyJson> =
    SideTable::new(&side_table::ROOMS_JOIN);

/// One join row: the live receipt every door reads, or its history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum JoinRow {
    Live(JoinReceipt),
    History { erased_history: JoinHistory },
}

/// The live receipt filed under `join_ref`, if any. A join that turned
/// history refuses: nothing files, answers or replays it again (FIX 4228).
///
/// # Errors
///
/// Storage errors, a row that cannot be read, or a history row.
pub(super) fn live_join(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    join_ref: &str,
) -> Result<Option<JoinReceipt>> {
    match JOIN_ROWS.get(store, txn, &join_ref.to_owned())? {
        None => Ok(None),
        Some(JoinRow::Live(receipt)) => Ok(Some(receipt)),
        Some(JoinRow::History { .. }) => Err(Error::InvalidConfig(
            "this join named a party that was erased; it is history, and nothing files, \
             answers or replays it again"
                .into(),
        )),
    }
}

impl JoinRow {
    /// The room and thread the join was filed for.
    pub(super) fn place(&self) -> (EntityId, Option<EntityId>) {
        match self {
            Self::Live(receipt) => (receipt.request.room, receipt.request.branch),
            Self::History { erased_history } => {
                (erased_history.request.room, erased_history.request.branch)
            }
        }
    }
}

/// [`super::JoinSubject`] as history holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
enum HistorySubject {
    Person(RosterActor),
    Agent(RosterActor),
}

/// [`super::JoinRequest`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRequest {
    room: EntityId,
    #[serde(default)]
    branch: Option<EntityId>,
    subject: HistorySubject,
    paid: bool,
    #[serde(default)]
    spend_scope: Option<SpendScopeId>,
    intent_key: String,
}

/// [`RequiredParty`] as history holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryParty {
    Subject(HistorySubject),
    Payer(RosterActor),
    PayerUnknown,
    VaultAdmin { vault: u64 },
    RoomHost { room: EntityId },
}

/// [`ConsentNeed`] as history holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryNeed {
    part: ConsentPart,
    party: HistoryParty,
}

/// [`ConsentState`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryState<T> {
    Missing(HistoryNeed),
    Granted(T),
    Denied(ConsentDenial),
}

/// [`SpendConsent`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistorySpend {
    Paid {
        payer: RosterActor,
        granted_by: RosterActor,
        scope: SpendScopeId,
        unit: LeaseUnit,
        cap_units: u64,
        at_ms: u64,
    },
    NoPaidWork,
}

/// [`MembershipConsent`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryMembership {
    VaultOwner {
        person: RosterActor,
    },
    Member {
        person: RosterActor,
        grant: EntityId,
    },
    CompanionOfMember {
        companion: RosterActor,
        principal: RosterActor,
        grant: Option<EntityId>,
    },
    ScopedGuest {
        person: RosterActor,
        guest_grant: EntityId,
    },
    HouseAgent {
        org: EntityId,
    },
}

/// [`AdmissionBasis`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryBasis {
    RoomOwner,
    DelegatedHost,
    StandingHomeRoster,
    HostAnswer { answer_ref: String },
    ThroughPrincipal { principal: RosterActor },
}

/// [`super::AdmissionConsent`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryAdmission {
    room: EntityId,
    branch: Option<EntityId>,
    subject: HistorySubject,
    granted_by: RosterActor,
    basis: HistoryBasis,
}

/// [`super::ConsentSet`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryConsents {
    subject: HistoryState<RosterActor>,
    spend: HistoryState<HistorySpend>,
    membership: HistoryState<HistoryMembership>,
    admission: HistoryState<HistoryAdmission>,
}

/// [`JoinDecision`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryDecision {
    Ready,
    Hold { needs: Vec<HistoryNeed> },
    Refuse(JoinRefusal),
}

/// A join receipt as history holds it: [`JoinReceipt`]'s fields, each id
/// it named a [`RosterActor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JoinHistory {
    join_ref: String,
    intent_digest: String,
    request: HistoryRequest,
    #[serde(default)]
    history: HistoryChoice,
    filed_by: RosterActor,
    principal: Option<RosterActor>,
    answers: Vec<RecordedAnswer>,
    consents: HistoryConsents,
    decision: HistoryDecision,
    participation: Option<JoinParticipation>,
    filed_at: u64,
    decided_at: u64,
}

impl JoinHistory {
    /// `receipt` as history once each of `erased` was erased: each names no
    /// one. Its ref, digest, place, decision and times are as filed.
    ///
    /// # Errors
    ///
    /// A receipt that does not take history's shape, which no stored
    /// receipt is.
    pub(super) fn of(receipt: &JoinReceipt, erased: &[EntityId]) -> Result<Self> {
        let value = serde_json::to_value(receipt)
            .map_err(|_| Error::InvariantViolation("join receipt encode"))?;
        let mut history: Self = serde_json::from_value(value)
            .map_err(|_| Error::InvariantViolation("join history shape"))?;
        for actor in erased {
            history.forget(*actor);
        }
        Ok(history)
    }

    /// Takes `actor` out of every party this history names (FIX 4228).
    /// Whether it named the actor.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = self.request.subject.forget(actor);
        named |= self.filed_by.forget(actor);
        if let Some(principal) = &mut self.principal {
            named |= principal.forget(actor);
        }
        for answer in &mut self.answers {
            named |= answer.by.forget(actor);
            named |= answer.actor.forget(actor);
        }
        named |= self.consents.forget(actor);
        named |= match &mut self.decision {
            HistoryDecision::Ready => false,
            HistoryDecision::Hold { needs } => {
                let mut held = false;
                for need in needs {
                    held |= need.party.forget(actor);
                }
                held
            }
            HistoryDecision::Refuse(JoinRefusal::Denied { party, .. }) => party.forget(actor),
            HistoryDecision::Refuse(_) => false,
        };
        named
    }
}

impl HistorySubject {
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Person(by) | Self::Agent(by) => by.forget(actor),
        }
    }
}

impl HistoryParty {
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Subject(subject) => subject.forget(actor),
            Self::Payer(payer) => payer.forget(actor),
            Self::PayerUnknown | Self::VaultAdmin { .. } | Self::RoomHost { .. } => false,
        }
    }
}

impl<T> HistoryState<T> {
    /// Takes `actor` out of the need, the denial, or by `granted` out of
    /// what was granted.
    fn forget(&mut self, actor: EntityId, granted: impl FnOnce(&mut T) -> bool) -> bool {
        match self {
            Self::Missing(need) => need.party.forget(actor),
            Self::Granted(value) => granted(value),
            Self::Denied(denial) => denial.party.forget(actor),
        }
    }
}

impl HistoryConsents {
    fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = self.subject.forget(actor, |by| by.forget(actor));
        named |= self.spend.forget(actor, |spend| match spend {
            HistorySpend::Paid {
                payer, granted_by, ..
            } => {
                let paid = payer.forget(actor);
                granted_by.forget(actor) | paid
            }
            HistorySpend::NoPaidWork => false,
        });
        named |= self
            .membership
            .forget(actor, |membership| match membership {
                HistoryMembership::VaultOwner { person }
                | HistoryMembership::Member { person, .. }
                | HistoryMembership::ScopedGuest { person, .. } => person.forget(actor),
                HistoryMembership::CompanionOfMember {
                    companion,
                    principal,
                    ..
                } => {
                    let attends = companion.forget(actor);
                    principal.forget(actor) | attends
                }
                HistoryMembership::HouseAgent { .. } => false,
            });
        named |= self.admission.forget(actor, |admission| {
            let mut named = admission.subject.forget(actor);
            named |= admission.granted_by.forget(actor);
            if let HistoryBasis::ThroughPrincipal { principal } = &mut admission.basis {
                named |= principal.forget(actor);
            }
            named
        });
        named
    }
}

/// Whether `need` waits on `actor`.
fn need_names(need: &ConsentNeed, actor: EntityId) -> bool {
    match need.party {
        RequiredParty::Subject(subject) => subject.id() == actor,
        RequiredParty::Payer(payer) => payer == actor,
        RequiredParty::PayerUnknown
        | RequiredParty::VaultAdmin { .. }
        | RequiredParty::RoomHost { .. } => false,
    }
}

/// Whether `state` names `actor` in its need, or by `granted` in what it
/// granted.
fn state_names<T>(state: &ConsentState<T>, actor: EntityId, granted: impl Fn(&T) -> bool) -> bool {
    match state {
        ConsentState::Missing(need) => need_names(need, actor),
        ConsentState::Granted(value) => granted(value),
        ConsentState::Denied(_) => false,
    }
}

/// Whether `receipt` names `actor` where only a live party's id can stand
/// (FIX 4228): its subject, a payer, a member, companion or principal, an
/// admitted subject or the principal it attends through, or a party a need
/// waits on. The answers and consents that record who gave them as a
/// [`RosterActor`] name no one by forgetting, not by this.
pub(super) fn links(receipt: &JoinReceipt, actor: EntityId) -> bool {
    let consents = &receipt.consents;
    receipt.request.subject.id() == actor
        || state_names(&consents.subject, actor, |_| false)
        || state_names(
            &consents.spend,
            actor,
            |spend| matches!(spend, SpendConsent::Paid { payer, .. } if *payer == actor),
        )
        || state_names(&consents.membership, actor, |membership| match membership {
            MembershipConsent::VaultOwner { person }
            | MembershipConsent::Member { person, .. }
            | MembershipConsent::ScopedGuest { person, .. } => *person == actor,
            MembershipConsent::CompanionOfMember {
                companion,
                principal,
                ..
            } => *companion == actor || *principal == actor,
            MembershipConsent::HouseAgent { .. } => false,
        })
        || state_names(&consents.admission, actor, |admission| {
            admission.subject.id() == actor
                || matches!(admission.basis, AdmissionBasis::ThroughPrincipal { principal } if principal == actor)
        })
        || matches!(&receipt.decision, JoinDecision::Hold { needs } if needs.iter().any(|need| need_names(need, actor)))
}
