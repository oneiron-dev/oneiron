//! The ladder from verified records (ARCH-0082 #ladder; ROLES-CHECKIN P2.2,
//! piece 2c; Engine ruling P22-SHAPE Q3, Q4 and Q9 = A).
//!
//! [`VerifiedChain`] names each rung's holders from verified records only:
//!
//! * rung 2, the grantor: the `delegated_by` principal of the asker's live
//!   grant (a delegate's parent, or the owner who minted an owner-agent
//!   grant), else the principal a companion person was onboarded for;
//! * rung 3, the next holders up the chain: every other live holder of the
//!   grantor's role on the vault the asker's grant is a membership of;
//! * rung 4, the Owner role: the vault's live owners.
//!
//! A rung pins only holders no earlier rung of the same ask pinned, so an
//! owner who was also the grantor is asked once, and the asker never.
//!
//! Operational lineage is no grantor: a spawn's parent attempt, the requester
//! of queued work and the filer of a house binding are not stored as a
//! principal (FIX rows CHECK-IN-SPAWN-PARENT-PRINCIPAL and
//! CHECK-IN-HOUSE-BINDER), so such a rung is skipped with its missing link
//! named. An agent that holds the Owner role joins rung 4 with canon's PR 4.
//!
//! A holder may answer while its standing admits the act: a live person, or
//! an enabled, active agent definition, that is not the asker, and is a live
//! owner or holds a live grant on the asker's vault (conferring now, its
//! pact not inactive) whose verbs admit the exact verb,
//! and whose own check-in for the act would not wait (Q9). A person's answer
//! is their own judgment (Q4), so the unsure test and the model check, which
//! bound a model, do not apply to it; an agent's verdict is its model's
//! judgment, so its own check-in must go. Standing rows are not read for a
//! holder: the pending row keeps the effect's digest, not the bounds a
//! standing row covers.

use super::mode::CheckInMode;
use super::pending::{
    HolderAnswer, HolderKind, PendingCheckIn, Rung, RungHolder, RungMembers, RungResolver,
};
use super::resolve::{
    CheckInAnswer, CheckInRequest, ResolvedMode, UnsureTest, check_in, resolve_mode,
};
use super::role_preset::RolePreset;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{
    AgentVerbClasses, FederationGrant, FederationGrantScope, decode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// An agent holder's verdict on a pending check-in, given when the ask
/// enters the agent's rung. The caller supplies it: the agent's own run
/// judges the ask (P22-SHAPE Q4 = A).
pub(crate) trait AgentHolderVerdict {
    /// `None`: no verdict, and the agent passes the ask up.
    fn verdict(&self, pending: &PendingCheckIn, agent: EntityId) -> Option<HolderAnswer>;
}

/// No agent gives a verdict: every agent holder passes the ask up.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2e's host builds the chain; until then only the test door does"
    )
)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoAgentVerdict;

impl AgentHolderVerdict for NoAgentVerdict {
    fn verdict(&self, _pending: &PendingCheckIn, _agent: EntityId) -> Option<HolderAnswer> {
        None
    }
}

/// The ladder from verified records, with the caller's agent verdicts.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2e's host builds the chain; until then only the test door does"
    )
)]
pub(crate) struct VerifiedChain<'a> {
    verdicts: &'a dyn AgentHolderVerdict,
}

#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2e's host builds the chain; until then only the test door does"
    )
)]
impl<'a> VerifiedChain<'a> {
    pub(crate) fn new(verdicts: &'a dyn AgentHolderVerdict) -> Self {
        Self { verdicts }
    }
}

impl RungResolver for VerifiedChain<'_> {
    fn members(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        pending: &PendingCheckIn,
        rung: Rung,
    ) -> Result<RungMembers> {
        if rung == Rung::Owner {
            return owner_members(vault, txn, pending);
        }
        let Some(grant) = asker_grant_in_txn(vault, txn, pending)? else {
            return Ok(missing(
                "the asker's grant is not a live grant naming the asker",
            ));
        };
        let Some(grantor) = grantor_in_txn(vault, txn, pending, &grant)? else {
            return Ok(missing(
                "no verified grantor: the grant names no delegated_by, the asker is no \
                 onboarded companion, and a spawn parent's or house binder's principal is not \
                 stored",
            ));
        };
        match rung {
            Rung::Grantor => Ok(match holder_of_in_txn(vault, txn, grantor)? {
                Some(holder) if grantor != pending.asker => RungMembers::Holders(vec![holder]),
                _ => missing("the grantor is no live person or agent other than the asker"),
            }),
            Rung::ChainHolders => chain_holder_members(vault, txn, pending, &grant, grantor),
            Rung::Owner => owner_members(vault, txn, pending),
        }
    }

    fn may_answer(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        pending: &PendingCheckIn,
        holder: &RungHolder,
        now: u64,
    ) -> Result<bool> {
        if holder.principal == pending.asker
            || holder_of_in_txn(vault, txn, holder.principal)?.as_ref() != Some(holder)
        {
            return Ok(false);
        }
        for (role, holds_power) in
            holder_standing_in_txn(vault, txn, pending, holder.principal, now)?
        {
            let request = CheckInRequest {
                act: pending.act,
                role,
                holds_power,
                explicit_mode: None,
                standing_row: None,
            };
            let admits = match holder.kind {
                HolderKind::Person => match resolve_mode(&request) {
                    ResolvedMode::OwnProof => true,
                    ResolvedMode::Mode { mode, .. } => mode != CheckInMode::AlwaysAsk,
                    ResolvedMode::Propose | ResolvedMode::Absent => false,
                },
                HolderKind::Agent => {
                    matches!(check_in(&request, &OwnJudgment), CheckInAnswer::Go(_))
                }
            };
            if admits {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn agent_verdict(&self, pending: &PendingCheckIn, holder: &RungHolder) -> Option<HolderAnswer> {
        (holder.kind == HolderKind::Agent)
            .then(|| self.verdicts.verdict(pending, holder.principal))
            .flatten()
    }
}

/// A holder's answer is its own judgment: it is sure.
struct OwnJudgment;

impl UnsureTest for OwnJudgment {
    fn is_sure(&self) -> Result<bool> {
        Ok(true)
    }
}

/// Whether `principal` was pinned on an earlier rung of `pending`: a rung
/// above asks new holders, so nobody waits out a second wait for one ask.
fn asked_before(pending: &PendingCheckIn, principal: EntityId) -> bool {
    pending.rungs.iter().any(|entry| {
        entry
            .holders
            .iter()
            .any(|holder| holder.principal == principal)
    })
}

fn missing(link: &str) -> RungMembers {
    RungMembers::Missing(link.to_owned())
}

/// The asker's grant: the live FederationGrant row `pending.grant_ref` names
/// by its entity id, when it names the asker.
fn asker_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &PendingCheckIn,
) -> Result<Option<FederationGrant>> {
    let Ok(id) = EntityId::from_hex(&pending.grant_ref) else {
        return Ok(None);
    };
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &id)?
    else {
        return Ok(None);
    };
    Ok(decode_federation_grant_body(&body)
        .ok()
        .filter(|grant| grant.member_ref == pending.asker))
}

/// The grantor of the asker's `grant`: its `delegated_by`, else the
/// principal the asker, as a companion person, was onboarded for.
fn grantor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &PendingCheckIn,
    grant: &FederationGrant,
) -> Result<Option<EntityId>> {
    match grant.delegated_by {
        Some(by) => Ok(Some(by)),
        None => crate::workspace_roster::companion_principal_in_txn(vault, txn, pending.asker),
    }
}

/// `principal` as a holder: a live person, or an agent definition that is
/// live, enabled and active.
fn holder_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
) -> Result<Option<RungHolder>> {
    let kind = if crate::consent::person_is_live_in_txn(vault, txn, &principal)? {
        HolderKind::Person
    } else if crate::authority::live_agent_principal_in(
        &vault.store,
        txn,
        principal,
        EdgeActorClass::Agent,
    )? {
        HolderKind::Agent
    } else {
        return Ok(None);
    };
    Ok(Some(RungHolder { principal, kind }))
}

/// Rung 3: every live holder of the grantor's role on the asker's vault but
/// the grantor and the asker.
fn chain_holder_members(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &PendingCheckIn,
    grant: &FederationGrant,
    grantor: EntityId,
) -> Result<RungMembers> {
    let FederationGrantScope::Vault { vault_id } = grant.scope else {
        return Ok(missing("the asker's grant is no vault membership"));
    };
    let members = vault.shared_members_in_txn(txn, vault_id)?;
    let Some(role) = members
        .iter()
        .find(|(member, _)| *member == grantor)
        .map(|(_, role)| *role)
    else {
        return Ok(missing("the grantor holds no role on the vault"));
    };
    let mut holders = Vec::new();
    for (member, member_role) in members {
        if member_role != role
            || member == grantor
            || member == pending.asker
            || asked_before(pending, member)
        {
            continue;
        }
        if let Some(holder) = holder_of_in_txn(vault, txn, member)? {
            holders.push(holder);
        }
    }
    Ok(if holders.is_empty() {
        missing("no other live holder of the grantor's role this ask has not already asked")
    } else {
        RungMembers::Holders(holders)
    })
}

/// Rung 4: the vault's live owners but the asker.
fn owner_members(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &PendingCheckIn,
) -> Result<RungMembers> {
    let holders: Vec<RungHolder> = crate::policy_model::owners_in_txn(vault, txn)?
        .into_iter()
        .filter(|owner| *owner != pending.asker && !asked_before(pending, *owner))
        .map(|principal| RungHolder {
            principal,
            kind: HolderKind::Person,
        })
        .collect();
    Ok(if holders.is_empty() {
        missing("no live owner this ask has not already asked")
    } else {
        RungMembers::Holders(holders)
    })
}

/// The roles `holder` holds at `now` for the act, each with whether it holds
/// the power for the exact verb: Owner when it is a live owner; else each
/// live grant naming it on the asker's vault, whose verbs (or verb classes)
/// admit the verb or not.
fn holder_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &PendingCheckIn,
    holder: EntityId,
    now: u64,
) -> Result<Vec<(RolePreset, bool)>> {
    if crate::policy_model::owners_in_txn(vault, txn)?.contains(&holder) {
        return Ok(vec![(RolePreset::Owner, true)]);
    }
    let Some(asker_grant) = asker_grant_in_txn(vault, txn, pending)? else {
        return Ok(Vec::new());
    };
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let mut grants = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let id = id?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        if let Ok(grant) = decode_federation_grant_body(&body)
            && grant.member_ref == holder
            && grant.scope == asker_grant.scope
            && crate::federation::pact_admits_grant(&fold, &id, &grant)
        {
            grants.push(grant);
        }
    }
    let classes = AgentVerbClasses::for_grants_in_txn(&vault.store, txn, grants.iter())?;
    Ok(grants
        .iter()
        .filter(|grant| grant.confers_with_classes_at(now, &classes))
        .map(|grant| {
            let holds_power = grant.authority_scope.verbs.contains(&pending.verb)
                || grant.class_admits_verb(&pending.verb, &classes);
            (RolePreset::of_grant_role(grant.role), holds_power)
        })
        .collect())
}
