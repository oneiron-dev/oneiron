//! Who may draft and send for a signing principal (SGN06-WHO-MAY-SEND = B):
//! for each agent and each principal it acts for, the rung the owner chose
//! and the DEC-0006 standing Grant that holds his envelope, checked at each
//! use.
//!
//! The Grant is the authority: it lives in the one grant registry, under the
//! owner's Approved receipt, and one revoke ends it. The mode row only says
//! which rung and envelope are current, so a rung change revokes the old
//! Grant and mints the new one in the same owner write. Only an agent's own
//! act reads it: an owner's act, and the one send his approve-once press
//! released, need no Grant (FIX 9606).
//!
//! An `esign.*` class covers no Gate effect (no verb is spelled like one), so
//! a pair Grant widens nothing at the Gate: the agent's own Grant over the
//! e-sign act still decides whether the Gate holds it, and the pair Grant
//! decides for whom it may act.
use super::model::{EsignDocument, invalid};
use super::principals::{SigningAutonomy, verify_owner};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::edge::EdgeActorClass;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// The rung and envelope the owner chose for one agent and one principal.
/// Key: agent id16 + principal id16.
const AUTONOMY: SideTable<(EntityId, EntityId), AutonomyRow, Named> =
    SideTable::new(&side_table::ESIGN_AUTONOMY);
/// The send window an autonomous Grant has spent. Key: the Grant's ref.
const USAGE: SideTable<String, UsageRow, Named> = SideTable::new(&side_table::ESIGN_AUTONOMY_USAGE);

/// The class an autonomous rung's Grant names: the agent sends, reminds,
/// extends and voids for the principal, inside the envelope.
pub const ESIGN_SEND_CLASS: &str = "esign.send";
/// The class a draft or send-with-approval rung's Grant names: the agent
/// drafts for the principal, and each send waits for the owner's press.
pub const ESIGN_DRAFT_CLASS: &str = "esign.draft";

/// Why a rung and an envelope do not go together.
const ENVELOPE_RULE: &str = "an envelope of at least one action and one second goes with \
     autonomous_in_envelope, and with no other rung";

/// How many sends and reminders an autonomous agent may make for one
/// principal in one window. More actions, or a shorter window, is looser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignSendEnvelope {
    /// At least one.
    pub max_actions: u32,
    /// At least one second.
    pub window_secs: u64,
}

/// The owner's choice for one agent acting for one signing principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsignAutonomyRequest {
    /// A live agent of this vault.
    pub agent: EntityId,
    /// A PERSON or ORG, at its one current identity.
    pub principal: EntityId,
    pub rung: SigningAutonomy,
    /// Given exactly at `autonomous_in_envelope`.
    pub envelope: Option<EsignSendEnvelope>,
}

/// The owner's current choice, as [`Vault::esign_autonomy`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsignAutonomy {
    pub agent: EntityId,
    pub principal: EntityId,
    pub rung: SigningAutonomy,
    pub envelope: Option<EsignSendEnvelope>,
    /// The standing Grant the rung holds; `None` at `scoped_read`.
    pub grant_ref: Option<String>,
    /// The owner decision that chose it, lower-hex.
    pub decision_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyRow {
    rung: SigningAutonomy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    envelope: Option<EsignSendEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_ref: Option<String>,
    decision_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageRow {
    window_start: u64,
    spent: u32,
}

/// The Grant bound a rung holds for `agent` acting for `principal`, or
/// `None` at `scoped_read`.
fn rung_bound(
    agent: EntityId,
    principal: EntityId,
    rung: SigningAutonomy,
    envelope: Option<EsignSendEnvelope>,
) -> Result<Option<GrantBound>> {
    let selector = format!("principal:{}", principal.to_hex());
    let (class, envelope) = match (rung, envelope) {
        (SigningAutonomy::ScopedRead, None) => return Ok(None),
        (SigningAutonomy::Draft | SigningAutonomy::SendWithApproval, None) => {
            (ESIGN_DRAFT_CLASS, ActionEnvelope::new([selector])?)
        }
        (SigningAutonomy::AutonomousInEnvelope, Some(window))
            if window.max_actions > 0 && window.window_secs > 0 =>
        {
            (
                ESIGN_SEND_CLASS,
                ActionEnvelope::new([selector, format!("window_secs:{}", window.window_secs)])?
                    .with_budget(u64::from(window.max_actions))
                    .with_receipt_required(true),
            )
        }
        _ => return Err(invalid(ENVELOPE_RULE)),
    };
    Ok(Some(GrantBound::action(
        ActorBound::new(agent.to_hex())?,
        ActionClass::new(class)?,
        envelope.with_target(principal.to_hex())?,
    )?))
}

/// The one identity `principal` resolves to, or `None` when it resolves to
/// none or to several.
fn principal_head(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: &EntityId,
) -> Result<Option<EntityId>> {
    Ok(
        match vault.resolve_entity_in_txn(txn, principal)?.as_slice() {
            [head] => Some(*head),
            _ => None,
        },
    )
}

/// `principal` when it is a PERSON or ORG at its one current identity.
fn current_principal_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
) -> Result<EntityId> {
    if principal_head(vault, txn, &principal)? != Some(principal)
        || !matches!(
            vault.get_entity_type_in_txn(txn, &principal)?,
            Some(crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_ORG)
        )
    {
        return Err(invalid(
            "the signing principal must be a PERSON or ORG at its one current identity",
        ));
    }
    Ok(principal)
}

impl Vault {
    /// Applies the owner's rung for one agent acting for one signing
    /// principal: the Grant the old rung held is revoked and the new one
    /// minted, each with its receipt, in this one owner write. The same
    /// choice again changes nothing.
    ///
    /// # Errors
    /// No live owner authority; an agent that is not a live agent of this
    /// vault; a principal that is not one PERSON or ORG; an envelope given at
    /// a rung other than `autonomous_in_envelope`, or missing or empty there.
    pub fn apply_esign_autonomy(
        &self,
        owner: &AuthenticatedOwner,
        request: &EsignAutonomyRequest,
    ) -> Result<EsignAutonomy> {
        self.with_write_txn_grouped(|txn| {
            verify_owner(self, txn, owner)?;
            if !self.is_agent_principal_in_txn(txn, request.agent)? {
                return Err(invalid("the agent must be a live agent of this vault"));
            }
            let principal = current_principal_in(self, txn, request.principal)?;
            let key = (request.agent, principal);
            let bound = rung_bound(request.agent, principal, request.rung, request.envelope)?;
            let grant_ref = bound.as_ref().map(|bound| bound.digest().to_hex());
            let prior = AUTONOMY.get(&self.store, txn, &key)?;
            let held = prior.as_ref().and_then(|prior| prior.grant_ref.clone());
            // Draft and send-with-approval hold the same Grant: a move
            // between them keeps it live and only rewrites the mode row.
            let keeps =
                held == grant_ref && grant_live_in(self, txn, held.as_deref(), bound.as_ref())?;
            if let Some(prior) = prior.filter(|prior| keeps && prior.rung == request.rung) {
                return Ok(autonomy(key, prior));
            }
            if !keeps {
                if let Some(old) = &held {
                    self.revoke_consent_grant_in_txn(txn, owner, old)?;
                }
                if let Some(bound) = bound {
                    self.create_standing_grant_in_txn(txn, owner, bound)?;
                }
            }
            let row = AutonomyRow {
                rung: request.rung,
                envelope: request.envelope,
                grant_ref,
                decision_ref: owner.decision_id().to_hex(),
            };
            AUTONOMY.put(&self.store, txn, &key, &row)?;
            Ok(autonomy(key, row))
        })
    }

    /// The owner's current choice for `agent` acting for `principal`, or
    /// `None` when he made none (the agent may then neither draft nor send
    /// for it on its own).
    ///
    /// # Errors
    /// A storage failure.
    pub fn esign_autonomy(
        &self,
        agent: EntityId,
        principal: EntityId,
    ) -> Result<Option<EsignAutonomy>> {
        let txn = self.store.env.read_txn()?;
        let key = (agent, principal);
        Ok(AUTONOMY
            .get(&self.store, &txn, &key)?
            .map(|row| autonomy(key, row)))
    }

    /// Every choice the owner made, by agent and then principal.
    ///
    /// # Errors
    /// A storage failure.
    pub fn esign_autonomies(&self) -> Result<Vec<EsignAutonomy>> {
        let txn = self.store.env.read_txn()?;
        Ok(AUTONOMY
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(key, row)| autonomy(key, row))
            .collect())
    }
}

fn autonomy((agent, principal): (EntityId, EntityId), row: AutonomyRow) -> EsignAutonomy {
    EsignAutonomy {
        agent,
        principal,
        rung: row.rung,
        envelope: row.envelope,
        grant_ref: row.grant_ref,
        decision_ref: row.decision_ref,
    }
}

/// Whether the Grant `grant_ref` names is live with exactly `bound`; with
/// neither, the rung holds no Grant and nothing can be stale.
fn grant_live_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_ref: Option<&str>,
    bound: Option<&GrantBound>,
) -> Result<bool> {
    let (Some(grant_ref), Some(bound)) = (grant_ref, bound) else {
        return Ok(grant_ref.is_none() && bound.is_none());
    };
    Ok(
        crate::consent::standing_grant_row_in_txn(&vault.store, txn, grant_ref)?.is_some_and(
            |row| row.is_active() && row.bypass.is_none() && row.grant.bound() == bound,
        ),
    )
}

/// The principal an act is for: the one its document names, else the one
/// the call names. `None` when neither names one, or when the call names
/// another principal than the document.
fn acting_principal(named: Option<EntityId>, stated: Option<&str>) -> Option<EntityId> {
    let stated = match stated.map(EntityId::from_hex) {
        None => None,
        Some(Ok(stated)) => Some(stated),
        Some(Err(_)) => return None,
    };
    match (named, stated) {
        (Some(named), Some(stated)) if named != stated => None,
        (named, stated) => named.or(stated),
    }
}

/// The owner's current rung for `agent` acting for the one identity
/// `principal` resolves to, when the Grant it names is live with exactly the
/// bound that rung rebuilds: the row, and the Grant's ref. `None` when he
/// chose none, or its Grant was revoked or no longer matches.
fn live_rung_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    principal: EntityId,
) -> Result<Option<AutonomyRow>> {
    let Some(head) = principal_head(vault, txn, &principal)? else {
        return Ok(None);
    };
    let Some(row) = AUTONOMY.get(&vault.store, txn, &(agent, head))? else {
        return Ok(None);
    };
    let bound = rung_bound(agent, head, row.rung, row.envelope)?;
    let rebuilt = bound.as_ref().map(|bound| bound.digest().to_hex());
    if rebuilt != row.grant_ref
        || !grant_live_in(vault, txn, row.grant_ref.as_deref(), bound.as_ref())?
    {
        return Ok(None);
    }
    Ok(Some(row))
}

/// The live autonomous Grant `agent` holds for the principal an act is for
/// (see [`acting_principal`]), with its envelope.
fn send_grant_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: Option<EntityId>,
    named: Option<EntityId>,
    stated: Option<&str>,
) -> Result<Option<(String, EsignSendEnvelope)>> {
    let (Some(agent), Some(principal)) = (agent, acting_principal(named, stated)) else {
        return Ok(None);
    };
    Ok(match live_rung_in(vault, txn, agent, principal)? {
        Some(AutonomyRow {
            rung: SigningAutonomy::AutonomousInEnvelope,
            envelope: Some(envelope),
            grant_ref: Some(grant_ref),
            ..
        }) => Some((grant_ref, envelope)),
        _ => None,
    })
}

/// Whether an agent's own act (no owner act, no press) may land under this
/// writer: its live autonomous Grant for the principal the act is for (the
/// one its document names, else the one the call names), and for an act that
/// contacts the recipients (`spends`: a send or a reminder) one free action in
/// the envelope's window, which it spends here. A window whose time has passed
/// starts again; a clock behind the window's start refuses.
pub(super) fn agent_act_admitted_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    agent: Option<EntityId>,
    (named, stated): (Option<EntityId>, Option<&str>),
    spends: bool,
    now: u64,
) -> Result<bool> {
    let Some((grant_ref, envelope)) = send_grant_in(vault, txn, agent, named, stated)? else {
        return Ok(false);
    };
    if !spends {
        return Ok(true);
    }
    let usage = match USAGE.get(&vault.store, txn, &grant_ref)? {
        Some(usage) if now < usage.window_start => return Ok(false),
        Some(usage) if now - usage.window_start < envelope.window_secs => usage,
        _ => UsageRow {
            window_start: now,
            spent: 0,
        },
    };
    if usage.spent >= envelope.max_actions {
        return Ok(false);
    }
    let spent = UsageRow {
        spent: usage.spent + 1,
        ..usage
    };
    USAGE.put(&vault.store, txn, &grant_ref, &spent)?;
    Ok(true)
}

/// Whether an agent's queued delivery still has its live autonomous Grant: a
/// revoked Grant, or a rung the owner lowered, holds the mint. The send spent
/// its action when it landed, so this spends none.
pub(super) fn agent_delivery_granted_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: Option<EntityId>,
    (named, stated): (Option<EntityId>, Option<&str>),
) -> Result<bool> {
    Ok(send_grant_in(vault, txn, agent, named, stated)?.is_some())
}

/// Admits a drafter to draft `draft`: a principal it names is a PERSON or
/// ORG at its one current identity; a human drafts as before; any other
/// caller's draft names its principal, and the owner gave that caller a rung
/// above `scoped_read` for it, whose Grant is live.
pub(super) fn admit_drafter_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    draft: &EsignDocument,
) -> Result<()> {
    let principal = draft
        .principal_ref
        .map(|principal| current_principal_in(vault, txn, principal))
        .transpose()?;
    if class == EdgeActorClass::Human {
        return Ok(());
    }
    let principal =
        principal.ok_or_else(|| invalid("an agent's draft must name its signing principal"))?;
    match live_rung_in(vault, txn, actor, principal)? {
        Some(row) if row.rung != SigningAutonomy::ScopedRead => Ok(()),
        _ => Err(invalid(
            "the owner gave this agent no live e-sign Grant to draft for the principal",
        )),
    }
}

/// An erased actor's rows go (FIX 3520): every choice naming it as the agent
/// or as the principal. The Grants they hold stay in the registry, where an
/// actor's erase handles them.
/// # Errors
/// A storage failure.
pub(crate) fn erase_esign_autonomy_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (agent, principal) in AUTONOMY.scan_keys(&vault.store, wtxn, &[])? {
        if agent == *actor || principal == *actor {
            AUTONOMY.delete(&vault.store, wtxn, &(agent, principal))?;
        }
    }
    Ok(())
}
