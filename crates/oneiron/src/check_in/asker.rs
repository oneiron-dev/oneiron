//! The asking side of the agent verbs `vault.check_in.preflight` and
//! `vault.check_in.open` (ARCH-0082 #composing; ROLES-CHECKIN P2.3b, piece
//! 2f; Engine ruling P23-SHAPE Q5, Q6, Q10 and Q11 = A).
//!
//! An ask names the verb whose act would run, where the effect sits and the
//! effect's digest. Its answer comes from live records in the caller's own
//! snapshot, never from the caller's word:
//!
//! * the act class is the verb row's own ([`verb_act_class()`]): a `read`
//!   verb goes on the power alone; an `unstated` verb answers unstated and
//!   opens nothing (its default is PR 3's, Q6);
//! * the caller is the vault owner, who holds every power and acts on its
//!   own proof, or an agent on its own live owner Grant that lists the verb
//!   (`principal_standing`, the rule every agent verb door reads): that
//!   Grant carries the agent's delegated Owner powers, and its bounds say
//!   whether it holds the power where the effect sits. The asker's role is
//!   its live membership row's on the Grant's vault, so a Deputy house reads
//!   the Deputy column; an agent with no membership, or at the Owner role
//!   before agent Owner keys, reads the Grant's own role, Delegate
//!   ([`grant_role`]; P24-SHAPE Q1 = A). An agent with no such Grant lacks
//!   the power: absent, or propose where a role it reads may propose the
//!   act;
//! * a person who is not the vault owner asks on their live membership row
//!   on this vault's shared vault, which stands for the Grant (Engine ruling
//!   CHECKIN-PERSON-GRANT = A): the row is the grant an open names, its
//!   roster role is the role, and the power is that role's cell for the act
//!   class (CHECKIN-PERSON-POWER = A): a mode or own proof holds it, an
//!   if-named cell holds it when the row lists the verb, and propose or no
//!   verb do not; the row's bounds must cover where the effect sits. A
//!   person's act is their own judgment, as at the membership doors: an act
//!   asked when unsure goes, and an act that always asks waits. Any other
//!   caller is refused (Q10);
//! * no explicit mode row is read (the change path is PR 3), no standing row
//!   covers an ask by digest, and the unsure test is always unsure: no
//!   decision model judges an agent's act yet, so an act asked when unsure
//!   waits (Q5).

use super::act_class::ActClass;
use super::chain::{
    covers_effect, grant_in_txn, grant_role, membership_role_in_txn, person_holds_power,
};
use super::mode::CheckInMode;
use super::policy::CheckInScope;
use super::resolve::{
    CheckInAnswer, CheckInRequest, ResolvedMode, UnsureTest, WaitReason, check_in_with_mode,
    resolve_mode,
};
use super::role_preset::RolePreset;
use super::verb_act_class::{VerbActClass, verb_act_class};
use crate::authority::{NoStanding, principal_standing_covering_or_lapse_in_txn};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{AgentVerbClasses, FederationGrant};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult,
};

/// The production unsure test until a decision model judges an agent's act:
/// always unsure, so an act asked when unsure waits and asks (P23-SHAPE Q5
/// = A; canon #modes "Unsure, refusal or error: ask"). A caller can never
/// claim "sure".
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AlwaysUnsure;

impl UnsureTest for AlwaysUnsure {
    fn is_sure(&self) -> Result<bool> {
        Ok(false)
    }
}

/// Why an act goes, as the verbs report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AskGo {
    /// A `read` verb: the power is the whole check.
    Read,
    /// The mode is `NeverAsk`.
    NeverAsk,
    /// The caller acts on its own proof: the vault owner, or a role whose
    /// cell is its own proof.
    OwnProof,
    /// A person's act asked when unsure: their own judgment, they are sure.
    Sure,
}

impl AskGo {
    /// The wire token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::NeverAsk => "never_ask",
            Self::OwnProof => "own_proof",
            Self::Sure => "sure",
        }
    }
}

/// The answer to one ask, before anything is opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AskVerdict {
    Go {
        reason: AskGo,
        /// `None` for a `read` verb.
        act: Option<ActClass>,
    },
    /// The act waits for a proof from the ladder; `open` opens it under
    /// `grant`, the asker's own live Grant.
    Wait {
        asker: EntityId,
        grant: EntityId,
        act: ActClass,
        mode: CheckInMode,
        reason: WaitReason,
    },
    /// No power; a role the caller holds may open a proposal to a holder.
    /// Proposals are not built in P2.3.
    Propose { act: ActClass },
    /// No power, and no proposal path.
    Absent { why: &'static str },
    /// The verb's row states no proven class (`unstated`): nothing opens.
    Unstated,
}

const NO_GRANT_LISTS_VERB: &str = "no live owner Grant of the caller lists the verb";
const PACT_LAPSED: &str = "the shared vault's pact lapse took the caller's Grant";
const BOUNDS_MISS: &str = "the caller's Grant does not reach where the effect sits";
const ROLE_LACKS_POWER: &str = "the caller's role does not hold the power for this act";
const MEMBERSHIP_BOUNDS_MISS: &str =
    "the caller's membership row does not reach where the effect sits";

/// The caller as the verbs admit it.
enum Asker {
    Owner,
    /// An agent and the live owner Grant listing the verb, at the role it
    /// reads ([`grant_role`]).
    Agent {
        agent: EntityId,
        grant: EntityId,
        role: RolePreset,
        holds_power: bool,
    },
    /// An agent no live owner Grant lists the verb for, with the roles its
    /// live owner Grants read.
    Unpowered {
        roles: Vec<RolePreset>,
        why: &'static str,
    },
}

/// Judges one ask: `memory`'s caller asks whether `verb`'s act at `scope`
/// may run, in `txn`. Writes nothing.
///
/// # Errors
///
/// BAD_REQUEST for a name no verb row has; FORBIDDEN for a caller that is
/// neither the live vault owner nor an agent, or whose actor binding or
/// presented credential is not live; storage errors.
pub(crate) fn judge_ask_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
    scope: &CheckInScope,
) -> MemoryResult<AskVerdict> {
    let Some(class) = verb_act_class(verb) else {
        return Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            format!("no verb row is named `{verb}`"),
            &["Name the verb whose act would run, as its row names it."],
        ));
    };
    if let Some(member) = member_asker_in_txn(memory, txn, verb, class, scope)? {
        return Ok(judge_member_ask(&member, class));
    }
    let asker = asker_in_txn(memory, txn, verb, scope)?;
    Ok(match (asker, class) {
        (Asker::Owner, VerbActClass::Read) => AskVerdict::Go {
            reason: AskGo::Read,
            act: None,
        },
        (Asker::Owner, VerbActClass::Act(act)) => AskVerdict::Go {
            reason: AskGo::OwnProof,
            act: Some(act),
        },
        (
            Asker::Agent {
                holds_power: false, ..
            },
            VerbActClass::Read | VerbActClass::Unstated,
        ) => AskVerdict::Absent { why: BOUNDS_MISS },
        (Asker::Unpowered { why, .. }, VerbActClass::Read | VerbActClass::Unstated) => {
            AskVerdict::Absent { why }
        }
        (Asker::Owner | Asker::Agent { .. }, VerbActClass::Unstated) => AskVerdict::Unstated,
        (Asker::Agent { .. }, VerbActClass::Read) => AskVerdict::Go {
            reason: AskGo::Read,
            act: None,
        },
        (
            Asker::Agent {
                agent,
                grant,
                role,
                holds_power,
            },
            VerbActClass::Act(act),
        ) => judge_act(agent, grant, role, holds_power, act),
        (Asker::Unpowered { roles, why }, VerbActClass::Act(act)) => {
            let proposes = roles.iter().any(|&role| {
                resolve_mode(&CheckInRequest {
                    act,
                    role,
                    holds_power: false,
                    explicit_mode: None,
                    standing_row: None,
                }) == ResolvedMode::Propose
            });
            if proposes || act == ActClass::Erase {
                AskVerdict::Propose { act }
            } else {
                AskVerdict::Absent { why }
            }
        }
    })
}

/// A person who is not the vault owner, asking on their live membership row
/// (Engine ruling CHECKIN-PERSON-GRANT = A).
struct MemberAsker {
    person: EntityId,
    /// The membership row: the grant an open names, the ladder's rung 2
    /// reads who added the member from it.
    grant: EntityId,
    /// The row's roster role.
    role: RolePreset,
    /// Whether the role's cell holds the power and the row reaches where the
    /// effect sits ([`person_holds_power`]).
    holds_power: bool,
}

/// A person's ask on their membership row: a `read` verb goes where the row
/// reaches the effect; an act is the role's cell read as a person's own
/// judgment, as the membership doors read it (`effect`): own proof and
/// never-ask go, an act asked when unsure goes on their being sure, an act
/// that always asks waits, and a role without the power proposes or is
/// absent as its cell says.
fn judge_member_ask(member: &MemberAsker, class: VerbActClass) -> AskVerdict {
    let act = match class {
        VerbActClass::Read if member.holds_power => {
            return AskVerdict::Go {
                reason: AskGo::Read,
                act: None,
            };
        }
        VerbActClass::Unstated if member.holds_power => return AskVerdict::Unstated,
        VerbActClass::Read | VerbActClass::Unstated => {
            return AskVerdict::Absent {
                why: MEMBERSHIP_BOUNDS_MISS,
            };
        }
        VerbActClass::Act(act) => act,
    };
    let request = CheckInRequest {
        act,
        role: member.role,
        holds_power: member.holds_power,
        explicit_mode: None,
        standing_row: None,
    };
    match resolve_mode(&request) {
        ResolvedMode::OwnProof => AskVerdict::Go {
            reason: AskGo::OwnProof,
            act: Some(act),
        },
        ResolvedMode::Mode {
            mode: CheckInMode::NeverAsk,
            ..
        } => AskVerdict::Go {
            reason: AskGo::NeverAsk,
            act: Some(act),
        },
        ResolvedMode::Mode {
            mode: CheckInMode::AskWhenUnsure,
            ..
        } => AskVerdict::Go {
            reason: AskGo::Sure,
            act: Some(act),
        },
        ResolvedMode::Mode {
            mode: mode @ CheckInMode::AlwaysAsk,
            ..
        } => AskVerdict::Wait {
            asker: member.person,
            grant: member.grant,
            act,
            mode,
            reason: WaitReason::AlwaysAsk,
        },
        ResolvedMode::Propose => AskVerdict::Propose { act },
        ResolvedMode::Absent => AskVerdict::Absent {
            why: ROLE_LACKS_POWER,
        },
    }
}

/// The caller as a member, in `txn`: a live person, not the vault owner,
/// holding a live membership row on this vault's shared vault
/// ([`Vault::member_grant_in_txn`]) that confers now and whose pact is not
/// inactive. `None` for any other caller, whom [`asker_in_txn`] judges or
/// refuses. Its actor binding and any credential it presented are checked
/// first.
fn member_asker_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
    class: VerbActClass,
    scope: &CheckInScope,
) -> MemoryResult<Option<MemberAsker>> {
    let (person, actor_class) = (memory.actor(), memory.actor_class());
    if actor_class != EdgeActorClass::Human {
        return Ok(None);
    }
    let vault = memory.vault();
    verify_caller_in_txn(memory, txn)?;
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, person, actor_class)?
        || !crate::consent::person_is_live_in_txn(vault, txn, &person)?
    {
        return Ok(None);
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(None);
    };
    let Some((grant_id, _)) = vault.member_grant_in_txn(txn, creation.vault_id, person)? else {
        return Ok(None);
    };
    let Some(grant) = grant_in_txn(vault, txn, &grant_id)? else {
        return Ok(None);
    };
    let now = vault.instant_in_txn(txn)?.secs();
    let classes = AgentVerbClasses::for_grants_in_txn(&vault.store, txn, std::iter::once(&grant))?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if !grant.confers_with_classes_at(now, &classes)
        || !crate::federation::pact_admits_grant(&fold, &grant_id, &grant)
    {
        return Ok(None);
    }
    let role = RolePreset::of_grant_role(grant.role);
    let holds_power = match class {
        VerbActClass::Act(act) => person_holds_power(&grant, role, act, verb, &classes, scope),
        VerbActClass::Read | VerbActClass::Unstated => covers_effect(&grant, scope),
    };
    Ok(Some(MemberAsker {
        person,
        grant: grant_id,
        role,
        holds_power,
    }))
}

/// An agent's act under its Grant's `role`: the role's default (no explicit
/// row yet), the catastrophe and fixed rows, then the always-unsure test.
fn judge_act(
    agent: EntityId,
    grant: EntityId,
    role: RolePreset,
    holds_power: bool,
    act: ActClass,
) -> AskVerdict {
    let request = CheckInRequest {
        act,
        role,
        holds_power,
        explicit_mode: None,
        standing_row: None,
    };
    match resolve_mode(&request) {
        ResolvedMode::Mode { mode, .. } => match check_in_with_mode(act, mode, None, &AlwaysUnsure)
        {
            CheckInAnswer::Wait(reason) => AskVerdict::Wait {
                asker: agent,
                grant,
                act,
                mode,
                reason,
            },
            // No standing row is passed and the unsure test is never sure,
            // so only `NeverAsk` goes here.
            CheckInAnswer::Go(_) => AskVerdict::Go {
                reason: AskGo::NeverAsk,
                act: Some(act),
            },
            CheckInAnswer::Propose => AskVerdict::Propose { act },
            CheckInAnswer::Absent => AskVerdict::Absent {
                why: ROLE_LACKS_POWER,
            },
        },
        ResolvedMode::OwnProof => AskVerdict::Go {
            reason: AskGo::OwnProof,
            act: Some(act),
        },
        ResolvedMode::Propose => AskVerdict::Propose { act },
        ResolvedMode::Absent => AskVerdict::Absent {
            why: if holds_power {
                ROLE_LACKS_POWER
            } else {
                BOUNDS_MISS
            },
        },
    }
}

/// The caller's actor binding and any credential it presented, checked in
/// `txn`.
fn verify_caller_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused("the caller's credential is no longer live"));
    }
    Ok(())
}

/// The caller, in `txn`: its actor binding and any credential it presented
/// checked first; then the live vault owner, or an agent with its standing
/// for `verb`: the first of its Grants that stand for `verb` whose bounds
/// cover the effect at `scope`, else the first that stands (review round 1
/// of #7715 and #7716: an earlier Grant narrowed away from the effect hid a
/// later one that reaches it).
fn asker_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
    scope: &CheckInScope,
) -> MemoryResult<Asker> {
    let vault = memory.vault();
    let (actor, class) = (memory.actor(), memory.actor_class());
    verify_caller_in_txn(memory, txn)?;
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, actor, class)? {
        if !crate::consent::person_is_live_in_txn(vault, txn, &actor)? {
            return Err(refused("the vault owner is not a live person"));
        }
        return Ok(Asker::Owner);
    }
    if class != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner, a live member of the vault, nor an agent",
        ));
    }
    let covers = |grant: &FederationGrant| covers_effect(grant, scope);
    match principal_standing_covering_or_lapse_in_txn(
        vault,
        txn,
        actor,
        EdgeActorClass::Agent,
        verb,
        &covers,
    )? {
        Ok(standing) => {
            let Some(grant_id) = standing.grant else {
                return unpowered_in_txn(memory, txn, NO_GRANT_LISTS_VERB);
            };
            let Some(grant) = grant_in_txn(vault, txn, &grant_id)? else {
                return unpowered_in_txn(memory, txn, NO_GRANT_LISTS_VERB);
            };
            let membership = membership_role_in_txn(vault, txn, actor, &grant.scope)?;
            Ok(Asker::Agent {
                agent: actor,
                grant: grant_id,
                role: grant_role(&grant, membership),
                holds_power: covers_effect(&grant, scope),
            })
        }
        Err(NoStanding::PactStandingLapsed) => unpowered_in_txn(memory, txn, PACT_LAPSED),
        Err(NoStanding::NotStanding) => unpowered_in_txn(memory, txn, NO_GRANT_LISTS_VERB),
    }
}

/// An agent without the power, with the roles its live owner Grants read
/// ([`grant_role`]): each names it, stands now and was given by a live
/// owner.
fn unpowered_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    why: &'static str,
) -> MemoryResult<Asker> {
    let vault = memory.vault();
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let mut roles = Vec::new();
    for standing in crate::federation::agent_grants_for_store_in_txn(&vault.store, txn)? {
        if standing.grant.member_ref != memory.actor()
            || !standing.stands_at(now)
            || !owners.contains(&standing.delegated_by)
        {
            continue;
        }
        let membership = membership_role_in_txn(vault, txn, memory.actor(), &standing.grant.scope)?;
        roles.push(grant_role(&standing.grant, membership));
    }
    Ok(Asker::Unpowered { roles, why })
}

fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "vault.check_in takes the vault owner, a member asking on their live membership row, or an agent asking under its own live owner Grant: {why}"
        ),
        &[
            "Call as the owner, as a member of the vault, or as an agent the owner granted the verb whose act would run.",
        ],
    )
}
