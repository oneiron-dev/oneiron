//! One consent per party (OF-531): one typed decision that joins the
//! subject's own yes, a payer's spend, a vault's membership and a room's
//! admission before anyone takes part in a room.
//!
//! # Each consent comes from its own party
//!
//! The subject's yes is its own: a join its own actor or its principal files
//! carries it, and an invitation a board writer files for an unrelated
//! person (OF-417) waits on it until that person, or her principal, accepts
//! through the consent door. Spend is the payer's: the PERSON whose funds paid participation spends,
//! who accepted a cap for a scope ([`crate::agent_dispatch::SpendPayer`] on
//! the scope's root). Membership is the vault's: a live grant its Owner or
//! Admin wrote through the membership doors, read live here and never granted
//! here. Admission is the room's: its owner or a delegated host, or the
//! standing rule that a project home room seats its project's roster. None
//! stands in for another: a host's yes pays for nothing, a payer's yes admits
//! no one, an inviter's filing is no one's yes, and nothing here enrolls
//! anyone in a vault.
//!
//! # One snapshot, every missing party
//!
//! [`decide_join_in_txn`] loads each fact independently in one read
//! snapshot and names every party still missing, never only the first.
//! Forged or out-of-scope evidence refuses, and so does an explicit denial. A
//! Ready receipt is evidence, never a standing grant: [`require_join_in_txn`]
//! decides it again against live facts before each later effect, for exactly
//! the room or thread it was filed for. Nothing here counts or caps
//! participants.
//!
//! Entry: `decide_join_in_txn`.
//! Funding lives in `funding` and the per-part consent loads in `admission`.

use serde::{Deserialize, Serialize};

use super::join_receipt::{
    JOINS, JoinReceiptRef, READY, RecordedAnswer, RosterActor, join_ref, ready_key,
};
use super::{project, rooms, thread_audience_allows_in};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState, payer_binds_in_txn};
use crate::conversation::{RoomHost, room_host_in_txn};
use crate::error::{ClaimError, Error, Result};
use crate::federation::MembershipStanding;
use crate::llm::run_admission::LeaseUnit;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

pub use oneiron_contracts::room_join::{
    ConsentNeed, ConsentPart, JoinSubject, RequiredParty, RoomJoinHold,
};

mod admission;
mod funding;
pub(super) use self::admission::home_room_seats_in_txn;
use self::admission::{admission_in_txn, seats_hold_in_txn, spend_in_txn, subject_consent};
pub use self::funding::{RoomFunding, RoomSpend, room_funding_in_txn};

/// The room a piece of work runs in, and its thread when the work is
/// narrower than the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomWork {
    pub room: EntityId,
    pub branch: Option<EntityId>,
}

/// A request to take part in a room or one of its threads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub room: EntityId,
    /// A thread of the room, when the participation is narrower than it.
    #[serde(default)]
    pub branch: Option<EntityId>,
    pub subject: JoinSubject,
    /// Whether this participation will launch paid work. A join without paid
    /// work names no payer; a later paid launch must bring a payer's consent.
    pub paid: bool,
    /// The open scope, root or child, that paid work spends under. Its root
    /// carries the payer's consent.
    #[serde(default)]
    pub spend_scope: Option<SpendScopeId>,
    /// The caller's idempotency key: the same key replays this join.
    pub intent_key: String,
}

/// A party's recorded no. It stays a no once that party is erased, naming
/// no one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentDenial {
    pub party: RosterActor,
    pub answer_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState<T> {
    Missing(ConsentNeed),
    Granted(T),
    Denied(ConsentDenial),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendConsent {
    /// The payer said yes to this join, for a scope of a tree it funds.
    Paid {
        payer: EntityId,
        /// The actor that answered for the payer; no one once it was erased.
        granted_by: RosterActor,
        scope: SpendScopeId,
        unit: LeaseUnit,
        /// The cap of the tree's root, which the payer accepted.
        cap_units: u64,
        /// When the payer accepted that cap, in host milliseconds.
        at_ms: u64,
    },
    /// The participation launches no paid work. Only when `paid` is false.
    NoPaidWork,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipConsent {
    /// The owner of a personal vault.
    VaultOwner { person: EntityId },
    /// A live roster grant in a shared vault.
    Member { person: EntityId, grant: EntityId },
    /// A companion attends through its principal's membership. `grant` is
    /// `None` when the principal owns a personal vault.
    CompanionOfMember {
        companion: EntityId,
        principal: EntityId,
        grant: Option<EntityId>,
    },
    /// A live guest grant. It never counts as member standing and never
    /// enrolls anyone.
    ScopedGuest {
        person: EntityId,
        guest_grant: EntityId,
    },
    /// The workspace house mind, the org given a pen: institutional standing,
    /// read from the stored roster preset and valid only in its own
    /// workspace vault.
    HouseAgent { org: EntityId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionBasis {
    /// The subject's own PERSON owns the room.
    RoomOwner,
    /// The subject's own PERSON holds the room's delegate action.
    DelegatedHost,
    /// The room is a project home room and the subject sits on the project's
    /// effective roster (home-room members are the project's roster): a
    /// person by its PERSON or by a seat that acts as that person.
    StandingHomeRoster,
    /// The room's owner or a delegated host answered yes for this join.
    HostAnswer { answer_ref: String },
    /// A companion attends the rooms her member attends (ARCH-0063): her
    /// live principal stands in the room, on the home room's roster or as
    /// the ordinary room's owner or a current ledger member. Decided again
    /// on every use, so the principal leaving or losing standing ends it.
    ThroughPrincipal { principal: EntityId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConsent {
    pub room: EntityId,
    pub branch: Option<EntityId>,
    pub subject: JoinSubject,
    /// The host that admitted, the subject itself as host, the project
    /// whose roster seats it, or the principal a companion attends through;
    /// no one once that host was erased.
    pub granted_by: RosterActor,
    pub basis: AdmissionBasis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentSet {
    /// The subject's own yes: the actor that gave it, the subject or its
    /// principal.
    pub subject: ConsentState<RosterActor>,
    pub spend: ConsentState<SpendConsent>,
    pub membership: ConsentState<MembershipConsent>,
    pub admission: ConsentState<AdmissionConsent>,
}

impl ConsentSet {
    /// Takes `actor` out of who gave or refused each consent (FIX 3520):
    /// each granting or refusing party it was names no one. Whether any was.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = match &mut self.subject {
            ConsentState::Granted(by) => by.forget(actor),
            ConsentState::Denied(denial) => denial.party.forget(actor),
            ConsentState::Missing(_) => false,
        };
        named |= match &mut self.spend {
            ConsentState::Granted(SpendConsent::Paid { granted_by, .. }) => {
                granted_by.forget(actor)
            }
            ConsentState::Denied(denial) => denial.party.forget(actor),
            ConsentState::Granted(SpendConsent::NoPaidWork) | ConsentState::Missing(_) => false,
        };
        if let ConsentState::Denied(denial) = &mut self.membership {
            named |= denial.party.forget(actor);
        }
        named |= match &mut self.admission {
            ConsentState::Granted(admission) => admission.granted_by.forget(actor),
            ConsentState::Denied(denial) => denial.party.forget(actor),
            ConsentState::Missing(_) => false,
        };
        named
    }

    /// Every party still missing, in part order.
    #[must_use]
    pub fn needs(&self) -> Vec<ConsentNeed> {
        [
            missing(&self.subject),
            missing(&self.spend),
            missing(&self.membership),
            missing(&self.admission),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

fn missing<T>(state: &ConsentState<T>) -> Option<ConsentNeed> {
    match state {
        ConsentState::Missing(need) => Some(*need),
        _ => None,
    }
}

/// Why a join cannot go ahead under this intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRefusal {
    /// A party answered no; no one is named once that party was erased.
    Denied {
        part: ConsentPart,
        party: RosterActor,
        answer_ref: String,
    },
    /// The subject is not a live PERSON or AGENT_DEF.
    UnknownSubject,
    /// The subject is a workspace house mind outside its own workspace vault,
    /// where it holds no standing.
    ForeignHouseAgent { org: EntityId },
    /// The room is not a live room, or the branch is not one of its threads.
    UnknownRoom,
    /// The named spend scope does not exist.
    UnknownSpendScope { scope: SpendScopeId },
    /// The scope's payer evidence does not bind its grantor to the payer.
    ForgedPayer { scope: SpendScopeId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinDecision {
    Ready,
    Hold { needs: Vec<ConsentNeed> },
    Refuse(JoinRefusal),
}

/// Decides `request` in one snapshot: each fact loaded independently, with
/// the answers parties recorded for this exact request. A request no one
/// filed carries no subject's yes.
pub fn decide_join_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
    now: u64,
) -> Result<(JoinDecision, ConsentSet)> {
    let filed = JOINS
        .get(&vault.store, txn, &join_ref(request)?)?
        .filter(|receipt| receipt.request == *request);
    let (principal, answers) = filed.map_or((None, Vec::new()), |receipt| {
        (receipt.principal_id(), receipt.answers)
    });
    decide_with_in_txn(vault, txn, request, principal, &answers, now)
}

/// [`decide_join_in_txn`] over the answers and principal a receipt holds.
pub(super) fn decide_with_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
    principal: Option<EntityId>,
    answers: &[RecordedAnswer],
    now: u64,
) -> Result<(JoinDecision, ConsentSet)> {
    let subject = subject_consent(request, answers);
    let spend = spend_in_txn(vault, txn, request, answers)?;
    let membership = membership_in_txn(vault, txn, &request.subject, principal, now)?;
    let admission = admission_in_txn(vault, txn, request, answers, &membership.state, now)?;
    let refusal = subject
        .refusal
        .or(spend.refusal)
        .or(membership.refusal)
        .or(admission.refusal);
    let consents = ConsentSet {
        subject: subject.state,
        spend: spend.state,
        membership: membership.state,
        admission: admission.state,
    };
    let decision = match refusal {
        Some(refusal) => JoinDecision::Refuse(refusal),
        None => {
            let needs = consents.needs();
            if needs.is_empty() {
                JoinDecision::Ready
            } else {
                JoinDecision::Hold { needs }
            }
        }
    };
    Ok((decision, consents))
}

/// Re-proves `subject`'s Ready join in `room` itself against live facts and
/// returns its receipt. With `scope`, the work is paid: the join must carry
/// its payer's consent, and `scope` must spend under the tree that payer
/// funds.
pub fn require_join_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    subject: &JoinSubject,
    scope: Option<&SpendScopeId>,
) -> Result<JoinReceiptRef> {
    require_join_for_branch_in_txn(vault, txn, room, None, subject, scope)
}

/// [`require_join_in_txn`] for exactly `branch` of `room`: only the receipt
/// filed for that branch counts (`None`: the room itself). A Ready join in
/// one thread never authorizes another thread, nor the room.
pub fn require_join_for_branch_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subject: &JoinSubject,
    scope: Option<&SpendScopeId>,
) -> Result<JoinReceiptRef> {
    let join = READY
        .get(&vault.store, txn, &ready_key(room, subject, branch))?
        .ok_or_else(|| not_joined("the subject has no Ready join in this room or thread"))?;
    let receipt = JOINS
        .get(&vault.store, txn, &join)?
        .ok_or(Error::CorruptedIndex("ready join has no receipt"))?;
    if receipt.request.room != room
        || receipt.request.branch != branch
        || receipt.request.subject != *subject
    {
        return Err(Error::CorruptedIndex(
            "ready join names another room or subject",
        ));
    }
    let now = vault.store.clock.now_recorded_at();
    let (decision, consents) = decide_with_in_txn(
        vault,
        txn,
        &receipt.request,
        receipt.principal_id(),
        &receipt.answers,
        now,
    )?;
    if decision != JoinDecision::Ready {
        return Err(not_joined("the join no longer holds against live facts"));
    }
    if let Some(scope) = scope {
        let ConsentState::Granted(SpendConsent::Paid { scope: paid, .. }) = &consents.spend else {
            return Err(not_joined(
                "paid work needs its payer's consent on the join",
            ));
        };
        let dispatcher = AgentDispatcher::new(vault);
        let root = |scope: &SpendScopeId| {
            dispatcher
                .scope_with_root_in_txn(txn, scope)
                .map(|found| found.map(|(_, root)| root.scope))
        };
        let launch_root = root(scope)?;
        if launch_root.is_none() || launch_root != root(paid)? {
            return Err(not_joined(
                "paid work spends under the tree its payer funds",
            ));
        }
    }
    Ok(JoinReceiptRef::for_join(&receipt.join_ref))
}

/// [`require_join_for_branch_in_txn`] for an actor a room door already
/// verified. Its subject is the one OF-529 resolves from stored facts, never
/// from a label or its class: a PERSON is a person, an AGENT_DEF with a live
/// PERSON subject anchor is that person's pen, and any other AGENT_DEF is an
/// agent.
pub fn require_actor_join_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
    scope: Option<&SpendScopeId>,
) -> Result<JoinReceiptRef> {
    let now = vault.store.clock.now_recorded_at();
    let subject = super::rooms::join_subject_for_actor_in_txn(vault, txn, actor, now)?;
    require_join_for_branch_in_txn(vault, txn, room, branch, &subject, scope)
}

fn not_joined(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

/// The PERSON an actor speaks for: itself when it is a PERSON, else the
/// PERSON its stored subject anchor names. `None` for anything else.
pub(crate) fn person_of_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    match vault.get_entity_type_in_txn(txn, &actor)? {
        Some(ENTITY_TYPE_PERSON) => Ok(Some(actor)),
        Some(ENTITY_TYPE_AGENT_DEF) => agent_person_in_txn(vault, txn, actor, at),
        _ => Ok(None),
    }
}

/// The PERSON an AGENT_DEF's stored subject anchor names; `None` for an
/// unanchored agent or one anchored to an ORG, which is the vault's own.
pub(super) fn agent_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    Ok(
        crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &agent, at)?
            .filter(|anchor| anchor.subject_kind == crate::subject_model::SubjectKind::Person)
            .map(|anchor| anchor.subject_ref),
    )
}

/// The most recent answer recorded for `part`.
fn latest(answers: &[RecordedAnswer], part: ConsentPart) -> Option<&RecordedAnswer> {
    answers.iter().rev().find(|answer| answer.part == part)
}

/// One part as loaded: its state, and the refusal when its evidence is
/// malformed, forged or out of scope, or a party said no.
struct Loaded<T> {
    state: ConsentState<T>,
    refusal: Option<JoinRefusal>,
}

impl<T> Loaded<T> {
    fn granted(consent: T) -> Self {
        Self {
            state: ConsentState::Granted(consent),
            refusal: None,
        }
    }

    fn missing(need: ConsentNeed) -> Self {
        Self {
            state: ConsentState::Missing(need),
            refusal: None,
        }
    }

    fn refused(need: ConsentNeed, refusal: JoinRefusal) -> Self {
        Self {
            state: ConsentState::Missing(need),
            refusal: Some(refusal),
        }
    }

    fn denied(answer: &RecordedAnswer) -> Self {
        Self {
            state: ConsentState::Denied(ConsentDenial {
                party: answer.by,
                answer_ref: answer.answer_ref.clone(),
            }),
            refusal: Some(JoinRefusal::Denied {
                part: answer.part,
                party: answer.by,
                answer_ref: answer.answer_ref.clone(),
            }),
        }
    }
}

/// Whose standing a subject stands on.
enum Standing {
    /// Not a live PERSON or AGENT_DEF.
    Unknown,
    /// A workspace house mind, in its own workspace vault or outside it.
    House {
        org: EntityId,
        own: bool,
    },
    /// The vault's own agent, with no live owner to stand through.
    Ownerless,
    Own(EntityId),
    Companion {
        companion: EntityId,
        principal: EntityId,
    },
}

fn standing_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &JoinSubject,
    principal: Option<EntityId>,
    at: u64,
) -> Result<Standing> {
    let person = match *subject {
        JoinSubject::Person(person) => {
            if !crate::consent::person_is_live_in_txn(vault, txn, &person)? {
                return Ok(Standing::Unknown);
            }
            person
        }
        JoinSubject::Agent(agent) => {
            if !matches!(
                crate::vault::live_entity_row_in_txn(&vault.store, txn, &agent)?,
                crate::vault::LiveEntityRow::Live { entity_type, .. }
                    if entity_type == ENTITY_TYPE_AGENT_DEF
            ) {
                return Ok(Standing::Unknown);
            }
            if let Some((org, own)) = house_org_in_txn(vault, txn, agent, at)? {
                return Ok(Standing::House { org, own });
            }
            match agent_person_in_txn(vault, txn, agent, at)? {
                Some(person) => person,
                // The vault's own agent stands through a live owner: the one
                // who filed for it, else the first.
                None => {
                    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
                    let owner = principal
                        .filter(|owner| owners.contains(owner))
                        .or_else(|| owners.first().copied());
                    return Ok(owner.map_or(Standing::Ownerless, Standing::Own));
                }
            }
        }
    };
    Ok(
        match super::codec::companion_principal_in_txn(vault, txn, person)? {
            Some(principal) => Standing::Companion {
                companion: person,
                principal,
            },
            None => Standing::Own(person),
        },
    )
}

/// The ORG `agent` stands for when it is a workspace house mind: a stored
/// roster preset names it as the house pen and its subject anchor names that
/// preset's ORG. `own` when the preset's workspace is this shared vault.
fn house_org_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    at: u64,
) -> Result<Option<(EntityId, bool)>> {
    let presets: Vec<_> = super::records::PRESET
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, row)| row.preset)
        .collect();
    if !presets.iter().any(|preset| preset.house_actor_ref == agent) {
        return Ok(None);
    }
    let Some(anchor) = crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &agent, at)?
        .filter(|anchor| anchor.subject_kind == crate::subject_model::SubjectKind::Org)
    else {
        return Ok(None);
    };
    let here = vault
        .shared_vault_creation_in_txn(txn)?
        .map(|creation| creation.vault_id);
    let mut found = None;
    for preset in presets {
        if preset.house_actor_ref != agent || preset.org_ref != anchor.subject_ref {
            continue;
        }
        let own = here == Some(preset.workspace_vault_id);
        if own || found.is_none() {
            found = Some((preset.org_ref, own));
        }
    }
    Ok(found)
}

enum PersonStanding {
    VaultOwner,
    Member(EntityId),
    Guest(EntityId),
}

/// A person's live standing: a grant in a shared vault, or the owner of a
/// personal one.
fn person_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Option<PersonStanding>> {
    match vault.shared_vault_creation_in_txn(txn)? {
        Some(creation) => Ok(vault
            .membership_standing_in_txn(txn, creation.vault_id, &person)?
            .map(|standing| match standing {
                MembershipStanding::Member { grant, .. } => PersonStanding::Member(grant),
                MembershipStanding::ScopedGuest { grant } => PersonStanding::Guest(grant),
            })),
        None => Ok(crate::policy_model::owners_in_txn(vault, txn)?
            .contains(&person)
            .then_some(PersonStanding::VaultOwner)),
    }
}

/// The vault's membership, read live. A missing standing waits on the
/// vault's Owner or Admin, who resolves it through the membership doors.
fn membership_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &JoinSubject,
    principal: Option<EntityId>,
    at: u64,
) -> Result<Loaded<MembershipConsent>> {
    let need = ConsentNeed {
        part: ConsentPart::Membership,
        party: RequiredParty::VaultAdmin {
            vault: vault
                .shared_vault_creation_in_txn(txn)?
                .map_or(0, |creation| creation.vault_id),
        },
    };
    let consent = match standing_of_in_txn(vault, txn, subject, principal, at)? {
        Standing::Unknown => return Ok(Loaded::refused(need, JoinRefusal::UnknownSubject)),
        // Institutional standing: no admin is asked for it, and outside its
        // own vault the house mind has none.
        Standing::House { org, own: true } => Some(MembershipConsent::HouseAgent { org }),
        Standing::House { org, own: false } => {
            return Ok(Loaded::refused(
                need,
                JoinRefusal::ForeignHouseAgent { org },
            ));
        }
        Standing::Ownerless => None,
        Standing::Own(person) => {
            person_standing_in_txn(vault, txn, person)?.map(|standing| match standing {
                PersonStanding::VaultOwner => MembershipConsent::VaultOwner { person },
                PersonStanding::Member(grant) => MembershipConsent::Member { person, grant },
                PersonStanding::Guest(guest_grant) => MembershipConsent::ScopedGuest {
                    person,
                    guest_grant,
                },
            })
        }
        // A companion attends through its principal's membership; a guest's
        // scoped grant is no membership to attend through.
        Standing::Companion {
            companion,
            principal,
        } => match person_standing_in_txn(vault, txn, principal)? {
            Some(PersonStanding::VaultOwner) => Some(MembershipConsent::CompanionOfMember {
                companion,
                principal,
                grant: None,
            }),
            Some(PersonStanding::Member(grant)) => Some(MembershipConsent::CompanionOfMember {
                companion,
                principal,
                grant: Some(grant),
            }),
            Some(PersonStanding::Guest(_)) | None => None,
        },
    };
    Ok(consent.map_or(Loaded::missing(need), Loaded::granted))
}

/// Whether `principal` stands in `room` for its companions to attend
/// through: seated by a project home room's roster (a person by its PERSON
/// or its own pen), or an ordinary room's owner or current ledger member.
pub(super) fn principal_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    principal: EntityId,
    at: u64,
) -> Result<bool> {
    if let Some((_, seats)) = home_room_seats_in_txn(vault, txn, room)? {
        return seats_hold_in_txn(vault, txn, &seats, &JoinSubject::Person(principal), at);
    }
    let own = WriteActor::new(principal, EdgeActorClass::Human);
    Ok(matches!(
        room_host_in_txn(vault, txn, room, own)?,
        Some(RoomHost::Owner)
    ) || vault.members_in_txn(txn, room)?.contains(&principal))
}
