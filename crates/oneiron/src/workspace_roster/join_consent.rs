//! Three consents, three parties (OF-531): one typed decision that joins a
//! payer's spend, a vault's membership and a room's admission before anyone
//! takes part in a room.
//!
//! # Each consent comes from its own party
//!
//! Spend is the payer's: the PERSON whose funds paid participation spends,
//! who accepted a cap for a scope ([`crate::agent_dispatch::SpendPayer`] on
//! the scope's root). Membership is the vault's: a live grant its Owner or
//! Admin wrote through the membership doors, read live here and never granted
//! here. Admission is the room's: its owner or a delegated host, or the
//! standing rule that a project home room seats its project's roster. None
//! stands in for another: a host's yes pays for nothing, a payer's yes admits
//! no one, and nothing here enrolls anyone in a vault.
//!
//! # One snapshot, every missing party
//!
//! [`decide_join_in_txn`] loads the three facts independently in one read
//! snapshot and names every party still missing, never only the first.
//! Forged or out-of-scope evidence refuses, and so does an explicit denial. A
//! Ready receipt is evidence, never a standing grant: [`require_join_in_txn`]
//! decides it again against live facts before each later effect, for exactly
//! the room or thread it was filed for. Nothing here counts or caps
//! participants.

use serde::{Deserialize, Serialize};

use super::join_receipt::{JOINS, JoinReceiptRef, READY, RecordedAnswer, join_ref, ready_key};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState, payer_binds_in_txn};
use crate::conversation::{RoomHost, room_host_in_txn};
use crate::error::{ClaimError, Error, Result};
use crate::federation::MembershipStanding;
use crate::llm::run_admission::LeaseUnit;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

/// Who asks to take part. Resolved from stored bindings, never from labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum JoinSubject {
    /// A PERSON: a human, or a companion, who is a person everywhere.
    Person(EntityId),
    /// An AGENT_DEF. An agent never takes a room seat.
    Agent(EntityId),
}

impl JoinSubject {
    #[must_use]
    pub const fn id(&self) -> EntityId {
        match self {
            Self::Person(id) | Self::Agent(id) => *id,
        }
    }
}

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

/// The three consents a join collects, one from each party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPart {
    Spend,
    Membership,
    Admission,
}

/// The party a missing consent waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredParty {
    /// The PERSON who funds the named scope; only they say yes for it.
    Payer(EntityId),
    /// No scope with a payer's consent is named yet: whoever will pay opens
    /// one and says yes. Never the room host's or the vault owner's funds.
    PayerUnknown,
    /// The vault's Owner or Admin, through the membership doors (add a
    /// member, grant guest access). `vault` is the shared vault's id; 0 is a
    /// personal vault, whose owner alone stands in it.
    VaultAdmin { vault: u64 },
    /// The room's owner or a delegated host.
    RoomHost { room: EntityId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentNeed {
    pub part: ConsentPart,
    pub party: RequiredParty,
}

/// A party's recorded no.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentDenial {
    pub party: EntityId,
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
        /// The actor that answered for the payer.
        granted_by: EntityId,
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
    /// effective roster (home-room members are the project's roster).
    StandingHomeRoster,
    /// The room's owner or a delegated host answered yes for this join.
    HostAnswer { answer_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConsent {
    pub room: EntityId,
    pub branch: Option<EntityId>,
    pub subject: JoinSubject,
    /// The host that admitted, the subject itself as host, or the project
    /// whose roster seats it.
    pub granted_by: EntityId,
    pub basis: AdmissionBasis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentSet {
    pub spend: ConsentState<SpendConsent>,
    pub membership: ConsentState<MembershipConsent>,
    pub admission: ConsentState<AdmissionConsent>,
}

impl ConsentSet {
    /// Every party still missing, in part order.
    #[must_use]
    pub fn needs(&self) -> Vec<ConsentNeed> {
        [
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
    /// A party answered no.
    Denied {
        part: ConsentPart,
        party: EntityId,
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

/// Decides `request` in one snapshot: the three facts loaded independently,
/// with the answers parties recorded for this exact request.
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
        (receipt.principal, receipt.answers)
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
    let spend = spend_in_txn(vault, txn, request, answers)?;
    let membership = membership_in_txn(vault, txn, &request.subject, principal, now)?;
    let admission = admission_in_txn(vault, txn, request, answers)?;
    let refusal = spend.refusal.or(membership.refusal).or(admission.refusal);
    let consents = ConsentSet {
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
        receipt.principal,
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
/// verified. Its subject comes from the actor's stored entity kind (a PERSON
/// is a person, an AGENT_DEF an agent), never from a label or its class.
pub fn require_actor_join_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
    scope: Option<&SpendScopeId>,
) -> Result<JoinReceiptRef> {
    let subject = match vault.get_entity_type_in_txn(txn, &actor)? {
        Some(ENTITY_TYPE_PERSON) => JoinSubject::Person(actor),
        Some(ENTITY_TYPE_AGENT_DEF) => JoinSubject::Agent(actor),
        _ => return Err(not_joined("only a person or an agent joins a room")),
    };
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

/// The payer's consent. Paid work runs only under a scope whose root a payer
/// funds, and only once that payer said yes to this join for that scope.
fn spend_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
    answers: &[RecordedAnswer],
) -> Result<Loaded<SpendConsent>> {
    if !request.paid {
        return Ok(Loaded::granted(SpendConsent::NoPaidWork));
    }
    let unknown = ConsentNeed {
        part: ConsentPart::Spend,
        party: RequiredParty::PayerUnknown,
    };
    let answer = latest(answers, ConsentPart::Spend);
    if let Some(answer) = answer
        && !answer.grant
    {
        return Ok(Loaded::denied(answer));
    }
    // A payer's yes names the scope it funds; else the request names one.
    let Some(scope) = answer
        .and_then(|answer| answer.spend_scope.clone())
        .or_else(|| request.spend_scope.clone())
    else {
        return Ok(Loaded::missing(unknown));
    };
    let Some((row, root)) = AgentDispatcher::new(vault).scope_with_root_in_txn(txn, &scope)? else {
        return Ok(Loaded::refused(
            unknown,
            JoinRefusal::UnknownSpendScope { scope },
        ));
    };
    let Some(payer) = root.payer else {
        return Ok(Loaded::missing(unknown));
    };
    let named = ConsentNeed {
        part: ConsentPart::Spend,
        party: RequiredParty::Payer(payer.party),
    };
    if !payer_binds_in_txn(vault, txn, &payer)? {
        return Ok(Loaded::refused(named, JoinRefusal::ForgedPayer { scope }));
    }
    // A closed tree spends nothing more: its payer is asked again.
    if row.state != SpendState::Open || root.state != SpendState::Open {
        return Ok(Loaded::missing(named));
    }
    // The payer's own yes to this join, for this scope. A cap is no consent.
    let Some(yes) = answer
        .filter(|answer| answer.by == payer.party && answer.spend_scope.as_ref() == Some(&scope))
    else {
        return Ok(Loaded::missing(named));
    };
    Ok(Loaded::granted(SpendConsent::Paid {
        payer: payer.party,
        granted_by: yes.actor,
        scope,
        unit: root.unit,
        cap_units: root.cap_units,
        at_ms: payer.at_ms,
    }))
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

/// Whether the request names a live room, and a thread of that room.
fn room_holds_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, request: &JoinRequest) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &request.room)? != Some(ENTITY_TYPE_CONVERSATION)
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &request.room)?.is_live()
    {
        return Ok(false);
    }
    let Some(branch) = request.branch else {
        return Ok(true);
    };
    if branch == request.room {
        return Ok(false);
    }
    if let Some(turn) = super::rooms::TURNS.get(&vault.store, txn, &branch)? {
        return Ok(turn.room_id == request.room.to_hex());
    }
    if vault.get_entity_type_in_txn(txn, &branch)?.is_none() {
        return Ok(false);
    }
    Ok(crate::conversation::room_for_record_in(vault, txn, branch)? == Some(request.room))
}

/// A project home room's project and effective seats; `None` for any other
/// room.
pub(super) fn home_room_seats_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<(EntityId, Vec<String>)>> {
    // The stored body, not only the auxiliary marker, identifies the
    // substrate, as the room audience reads it.
    let body = crate::conversation::body_in(vault, txn, room)?;
    if !body.extra.contains_key("project_id")
        && !body.extra.contains_key("memberIds")
        && !super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)?
    {
        return Ok(None);
    }
    let room = super::rooms::room_in(vault, txn, room)?;
    Ok(Some((
        EntityId::from_hex(&room.project_id)?,
        room.member_ids,
    )))
}

/// The room's admission. Addressing, a task assignment, a claim or presence
/// is never admission.
fn admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
    answers: &[RecordedAnswer],
) -> Result<Loaded<AdmissionConsent>> {
    let need = ConsentNeed {
        part: ConsentPart::Admission,
        party: RequiredParty::RoomHost { room: request.room },
    };
    if !room_holds_in_txn(vault, txn, request)? {
        return Ok(Loaded::refused(need, JoinRefusal::UnknownRoom));
    }
    let admitted = |granted_by, basis| {
        Loaded::granted(AdmissionConsent {
            room: request.room,
            branch: request.branch,
            subject: request.subject,
            granted_by,
            basis,
        })
    };
    if let Some(answer) = latest(answers, ConsentPart::Admission) {
        if !answer.grant {
            return Ok(Loaded::denied(answer));
        }
        // A host's yes stands while that host still holds the room.
        let host = WriteActor::new(answer.actor, EdgeActorClass::Human);
        if room_host_in_txn(vault, txn, request.room, host)?.is_some() {
            return Ok(admitted(
                answer.by,
                AdmissionBasis::HostAnswer {
                    answer_ref: answer.answer_ref.clone(),
                },
            ));
        }
    }
    if let JoinSubject::Person(person) = request.subject {
        let own = WriteActor::new(person, EdgeActorClass::Human);
        match room_host_in_txn(vault, txn, request.room, own)? {
            Some(RoomHost::Owner) => return Ok(admitted(person, AdmissionBasis::RoomOwner)),
            Some(RoomHost::Delegate) => return Ok(admitted(person, AdmissionBasis::DelegatedHost)),
            None => {}
        }
    }
    if let Some((project, seats)) = home_room_seats_in_txn(vault, txn, request.room)?
        && seats.contains(&request.subject.id().to_hex())
    {
        return Ok(admitted(project, AdmissionBasis::StandingHomeRoster));
    }
    Ok(Loaded::missing(need))
}
