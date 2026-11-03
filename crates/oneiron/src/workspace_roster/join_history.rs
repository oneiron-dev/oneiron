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
use crate::conversation::HistoryChoice;
use crate::deletion::carrier_actor_merged;
use crate::error::{Error, Result};
use crate::run_budget::LeaseUnit;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::workspace_roster::spend_scope::SpendScopeId;

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

/// Two copies of one actor slot as one under carrier equivalence (FIX 4871):
/// erase wins, and two live actors still conflict.
fn merged_actor(ours: RosterActor, theirs: RosterActor) -> Option<RosterActor> {
    carrier_actor_merged(ours, theirs, RosterActor::Erased)
}

/// Two copies of one recorded answer as one (FIX 4871): who it names
/// settles by the carrier rule, as a live copy's answer settles in
/// `carrier_erase::answer_erased_wins`, and the rest must match.
fn merged_answer(ours: &RecordedAnswer, theirs: &RecordedAnswer) -> Option<RecordedAnswer> {
    let by = merged_actor(ours.by, theirs.by)?;
    let actor = merged_actor(ours.actor, theirs.actor)?;
    let merged = RecordedAnswer {
        by,
        actor,
        ..ours.clone()
    };
    let other = RecordedAnswer {
        by,
        actor,
        ..theirs.clone()
    };
    (merged == other).then_some(merged)
}

fn merged_subject(ours: &HistorySubject, theirs: &HistorySubject) -> Option<HistorySubject> {
    match (ours, theirs) {
        (HistorySubject::Person(ours), HistorySubject::Person(theirs)) => {
            merged_actor(*ours, *theirs).map(HistorySubject::Person)
        }
        (HistorySubject::Agent(ours), HistorySubject::Agent(theirs)) => {
            merged_actor(*ours, *theirs).map(HistorySubject::Agent)
        }
        _ => None,
    }
}

fn merged_party(ours: &HistoryParty, theirs: &HistoryParty) -> Option<HistoryParty> {
    match (ours, theirs) {
        (HistoryParty::Subject(ours), HistoryParty::Subject(theirs)) => {
            merged_subject(ours, theirs).map(HistoryParty::Subject)
        }
        (HistoryParty::Payer(ours), HistoryParty::Payer(theirs)) => {
            merged_actor(*ours, *theirs).map(HistoryParty::Payer)
        }
        _ if ours == theirs => Some(*ours),
        _ => None,
    }
}

fn merged_need(ours: &HistoryNeed, theirs: &HistoryNeed) -> Option<HistoryNeed> {
    if ours.part != theirs.part {
        return None;
    }
    merged_party(&ours.party, &theirs.party).map(|party| HistoryNeed {
        part: ours.part,
        party,
    })
}

fn merged_denial(ours: &ConsentDenial, theirs: &ConsentDenial) -> Option<ConsentDenial> {
    if ours.answer_ref != theirs.answer_ref {
        return None;
    }
    merged_actor(ours.party, theirs.party).map(|party| ConsentDenial {
        party,
        answer_ref: ours.answer_ref.clone(),
    })
}

fn merged_state<T>(
    ours: &HistoryState<T>,
    theirs: &HistoryState<T>,
    granted: impl Fn(&T, &T) -> Option<T>,
) -> Option<HistoryState<T>> {
    match (ours, theirs) {
        (HistoryState::Missing(ours), HistoryState::Missing(theirs)) => {
            merged_need(ours, theirs).map(HistoryState::Missing)
        }
        (HistoryState::Granted(ours), HistoryState::Granted(theirs)) => {
            granted(ours, theirs).map(HistoryState::Granted)
        }
        (HistoryState::Denied(ours), HistoryState::Denied(theirs)) => {
            merged_denial(ours, theirs).map(HistoryState::Denied)
        }
        _ => None,
    }
}

fn merged_spend(ours: &HistorySpend, theirs: &HistorySpend) -> Option<HistorySpend> {
    match (ours, theirs) {
        (
            HistorySpend::Paid {
                payer: ours_payer,
                granted_by: ours_by,
                scope: ours_scope,
                unit: ours_unit,
                cap_units: ours_cap,
                at_ms: ours_at,
            },
            HistorySpend::Paid {
                payer: theirs_payer,
                granted_by: theirs_by,
                scope: theirs_scope,
                unit: theirs_unit,
                cap_units: theirs_cap,
                at_ms: theirs_at,
            },
        ) => {
            if ours_scope != theirs_scope
                || ours_unit != theirs_unit
                || ours_cap != theirs_cap
                || ours_at != theirs_at
            {
                return None;
            }
            Some(HistorySpend::Paid {
                payer: merged_actor(*ours_payer, *theirs_payer)?,
                granted_by: merged_actor(*ours_by, *theirs_by)?,
                scope: ours_scope.clone(),
                unit: ours_unit.clone(),
                cap_units: *ours_cap,
                at_ms: *ours_at,
            })
        }
        (HistorySpend::NoPaidWork, HistorySpend::NoPaidWork) => Some(HistorySpend::NoPaidWork),
        _ => None,
    }
}

fn merged_membership(
    ours: &HistoryMembership,
    theirs: &HistoryMembership,
) -> Option<HistoryMembership> {
    match (ours, theirs) {
        (
            HistoryMembership::VaultOwner { person: ours },
            HistoryMembership::VaultOwner { person: theirs },
        ) => merged_actor(*ours, *theirs).map(|person| HistoryMembership::VaultOwner { person }),
        (
            HistoryMembership::Member {
                person: ours,
                grant: ours_grant,
            },
            HistoryMembership::Member {
                person: theirs,
                grant: theirs_grant,
            },
        ) => {
            if ours_grant != theirs_grant {
                return None;
            }
            merged_actor(*ours, *theirs).map(|person| HistoryMembership::Member {
                person,
                grant: *ours_grant,
            })
        }
        (
            HistoryMembership::CompanionOfMember {
                companion: ours_companion,
                principal: ours_principal,
                grant: ours_grant,
            },
            HistoryMembership::CompanionOfMember {
                companion: theirs_companion,
                principal: theirs_principal,
                grant: theirs_grant,
            },
        ) => {
            if ours_grant != theirs_grant {
                return None;
            }
            Some(HistoryMembership::CompanionOfMember {
                companion: merged_actor(*ours_companion, *theirs_companion)?,
                principal: merged_actor(*ours_principal, *theirs_principal)?,
                grant: *ours_grant,
            })
        }
        (
            HistoryMembership::ScopedGuest {
                person: ours,
                guest_grant: ours_grant,
            },
            HistoryMembership::ScopedGuest {
                person: theirs,
                guest_grant: theirs_grant,
            },
        ) => {
            if ours_grant != theirs_grant {
                return None;
            }
            merged_actor(*ours, *theirs).map(|person| HistoryMembership::ScopedGuest {
                person,
                guest_grant: *ours_grant,
            })
        }
        _ if ours == theirs => Some(ours.clone()),
        _ => None,
    }
}

fn merged_basis(ours: &HistoryBasis, theirs: &HistoryBasis) -> Option<HistoryBasis> {
    match (ours, theirs) {
        (
            HistoryBasis::ThroughPrincipal { principal: ours },
            HistoryBasis::ThroughPrincipal { principal: theirs },
        ) => merged_actor(*ours, *theirs)
            .map(|principal| HistoryBasis::ThroughPrincipal { principal }),
        _ if ours == theirs => Some(ours.clone()),
        _ => None,
    }
}

fn merged_admission(
    ours: &HistoryAdmission,
    theirs: &HistoryAdmission,
) -> Option<HistoryAdmission> {
    if ours.room != theirs.room || ours.branch != theirs.branch {
        return None;
    }
    Some(HistoryAdmission {
        room: ours.room,
        branch: ours.branch,
        subject: merged_subject(&ours.subject, &theirs.subject)?,
        granted_by: merged_actor(ours.granted_by, theirs.granted_by)?,
        basis: merged_basis(&ours.basis, &theirs.basis)?,
    })
}

fn merged_consents(ours: &HistoryConsents, theirs: &HistoryConsents) -> Option<HistoryConsents> {
    Some(HistoryConsents {
        subject: merged_state(&ours.subject, &theirs.subject, |ours, theirs| {
            merged_actor(*ours, *theirs)
        })?,
        spend: merged_state(&ours.spend, &theirs.spend, merged_spend)?,
        membership: merged_state(&ours.membership, &theirs.membership, merged_membership)?,
        admission: merged_state(&ours.admission, &theirs.admission, merged_admission)?,
    })
}

fn merged_refusal(ours: &JoinRefusal, theirs: &JoinRefusal) -> Option<JoinRefusal> {
    match (ours, theirs) {
        (
            JoinRefusal::Denied {
                part: ours_part,
                party: ours_party,
                answer_ref: ours_ref,
            },
            JoinRefusal::Denied {
                part: theirs_part,
                party: theirs_party,
                answer_ref: theirs_ref,
            },
        ) => {
            if ours_part != theirs_part || ours_ref != theirs_ref {
                return None;
            }
            merged_actor(*ours_party, *theirs_party).map(|party| JoinRefusal::Denied {
                part: *ours_part,
                party,
                answer_ref: ours_ref.clone(),
            })
        }
        _ if ours == theirs => Some(ours.clone()),
        _ => None,
    }
}

fn merged_decision(ours: &HistoryDecision, theirs: &HistoryDecision) -> Option<HistoryDecision> {
    match (ours, theirs) {
        (HistoryDecision::Ready, HistoryDecision::Ready) => Some(HistoryDecision::Ready),
        (HistoryDecision::Hold { needs: ours }, HistoryDecision::Hold { needs: theirs }) => {
            if ours.len() != theirs.len() {
                return None;
            }
            let needs = ours
                .iter()
                .zip(theirs)
                .map(|(ours, theirs)| merged_need(ours, theirs))
                .collect::<Option<_>>()?;
            Some(HistoryDecision::Hold { needs })
        }
        (HistoryDecision::Refuse(ours), HistoryDecision::Refuse(theirs)) => {
            merged_refusal(ours, theirs).map(HistoryDecision::Refuse)
        }
        _ => None,
    }
}

/// Two copies of one settled join's history as one (FIX 4871): the union of
/// what each forgot, where each vault erased a different party. Every field
/// but who they name must match, and two live actors in one slot still
/// conflict, as live copies do. Answers union by their ref, as `merged_join`
/// settles a live copy's.
pub(super) fn join_history_erased_wins(
    ours: &JoinHistory,
    theirs: &JoinHistory,
) -> Option<JoinHistory> {
    if ours.join_ref != theirs.join_ref
        || ours.intent_digest != theirs.intent_digest
        || ours.request.room != theirs.request.room
        || ours.request.branch != theirs.request.branch
        || ours.request.paid != theirs.request.paid
        || ours.request.spend_scope != theirs.request.spend_scope
        || ours.request.intent_key != theirs.request.intent_key
        || ours.history != theirs.history
        || ours.participation != theirs.participation
        || ours.filed_at != theirs.filed_at
        || ours.decided_at != theirs.decided_at
    {
        return None;
    }
    let subject = merged_subject(&ours.request.subject, &theirs.request.subject)?;
    let mut answers = ours.answers.clone();
    for answer in &theirs.answers {
        match answers
            .iter_mut()
            .find(|held| held.answer_ref == answer.answer_ref)
        {
            Some(held) => {
                *held = merged_answer(held, answer)?;
            }
            None => answers.push(answer.clone()),
        }
    }
    answers.sort_by(|a, b| (a.at, &a.answer_ref).cmp(&(b.at, &b.answer_ref)));
    let principal = match (&ours.principal, &theirs.principal) {
        (Some(ours), Some(theirs)) => Some(merged_actor(*ours, *theirs)?),
        (None, None) => None,
        _ => return None,
    };
    Some(JoinHistory {
        join_ref: ours.join_ref.clone(),
        intent_digest: ours.intent_digest.clone(),
        request: HistoryRequest {
            room: ours.request.room,
            branch: ours.request.branch,
            subject,
            paid: ours.request.paid,
            spend_scope: ours.request.spend_scope.clone(),
            intent_key: ours.request.intent_key.clone(),
        },
        history: ours.history,
        filed_by: merged_actor(ours.filed_by, theirs.filed_by)?,
        principal,
        answers,
        consents: merged_consents(&ours.consents, &theirs.consents)?,
        decision: merged_decision(&ours.decision, &theirs.decision)?,
        participation: ours.participation,
        filed_at: ours.filed_at,
        decided_at: ours.decided_at,
    })
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
