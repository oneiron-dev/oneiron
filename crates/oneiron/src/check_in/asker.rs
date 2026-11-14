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
//!   Grant's role is the asker's role, and its bounds say whether it holds
//!   the power where the effect sits. An agent with no such Grant lacks the
//!   power: absent, or propose where a role its live Grants give may propose
//!   the act. Any other caller is refused (Q10; persons without a Grant are
//!   FIX row CHECK-IN-PERSON-CALLER-NO-GRANT);
//! * no explicit mode row is read (the change path is PR 3), no standing row
//!   covers an ask by digest, and the unsure test is always unsure: no
//!   decision model judges an agent's act yet, so an act asked when unsure
//!   waits (Q5).

use super::act_class::ActClass;
use super::chain::{covers_effect, grant_in_txn};
use super::mode::CheckInMode;
use super::policy::CheckInScope;
use super::resolve::{
    CheckInAnswer, CheckInRequest, ResolvedMode, UnsureTest, WaitReason, check_in_with_mode,
    resolve_mode,
};
use super::role_preset::RolePreset;
use super::verb_act_class::{VerbActClass, verb_act_class};
use crate::authority::{NoStanding, principal_standing_or_lapse_in_txn};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
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
}

impl AskGo {
    /// The wire token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::NeverAsk => "never_ask",
            Self::OwnProof => "own_proof",
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

/// The caller as the verbs admit it.
enum Asker {
    Owner,
    /// An agent and the live owner Grant listing the verb.
    Agent {
        agent: EntityId,
        grant: EntityId,
        role: RolePreset,
        holds_power: bool,
    },
    /// An agent no live owner Grant lists the verb for, with the roles its
    /// live owner Grants give it.
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

/// The caller, in `txn`: its actor binding and any credential it presented
/// checked first; then the live vault owner, or an agent with its standing
/// for `verb`.
fn asker_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
    scope: &CheckInScope,
) -> MemoryResult<Asker> {
    let vault = memory.vault();
    let (actor, class) = (memory.actor(), memory.actor_class());
    crate::memory::verify_actor_binding_in_txn(vault, txn, actor, class)?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused("the caller's credential is no longer live"));
    }
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, actor, class)? {
        if !crate::consent::person_is_live_in_txn(vault, txn, &actor)? {
            return Err(refused("the vault owner is not a live person"));
        }
        return Ok(Asker::Owner);
    }
    if class != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(vault, txn, actor, EdgeActorClass::Agent, verb)? {
        Ok(standing) => {
            let Some(grant_id) = standing.grant else {
                return unpowered_in_txn(memory, txn, NO_GRANT_LISTS_VERB);
            };
            let Some(grant) = grant_in_txn(vault, txn, &grant_id)? else {
                return unpowered_in_txn(memory, txn, NO_GRANT_LISTS_VERB);
            };
            Ok(Asker::Agent {
                agent: actor,
                grant: grant_id,
                role: RolePreset::of_grant_role(grant.role),
                holds_power: covers_effect(&grant, scope),
            })
        }
        Err(NoStanding::PactStandingLapsed) => unpowered_in_txn(memory, txn, PACT_LAPSED),
        Err(NoStanding::NotStanding) => unpowered_in_txn(memory, txn, NO_GRANT_LISTS_VERB),
    }
}

/// An agent without the power, with the roles its live owner Grants give
/// it: each names it, stands now and was given by a live owner.
fn unpowered_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    why: &'static str,
) -> MemoryResult<Asker> {
    let vault = memory.vault();
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let roles = crate::federation::agent_grants_for_store_in_txn(&vault.store, txn)?
        .into_iter()
        .filter(|standing| {
            standing.grant.member_ref == memory.actor()
                && standing.stands_at(now)
                && owners.contains(&standing.delegated_by)
        })
        .map(|standing| RolePreset::of_grant_role(standing.grant.role))
        .collect();
    Ok(Asker::Unpowered { roles, why })
}

fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "vault.check_in takes the vault owner, or an agent asking under its own live owner Grant: {why}"
        ),
        &["Call as the owner, or as an agent the owner granted the verb whose act would run."],
    )
}
