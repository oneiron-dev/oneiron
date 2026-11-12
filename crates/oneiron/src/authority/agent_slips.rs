//! The live issued slips of the vault's named agents (FIX
//! AGENT-GRANTLESS-VISIBLE; Engine RULING GRANTLESS-SHAPE Q4 = A, 12 Nov
//! 03:02): what an agent paired before the owner's Grants, or without his
//! proof, holds today. The serve-start backfill reads it to mint each
//! never-granted holder its default read Grant
//! ([`Vault::backfill_default_agent_grants`]).
//!
//! A slip counts when the authority fold counts its mint (adopted
//! checkpoint evidence included) and it is live now: within its lifetime,
//! its ancestry, Grant, invitation and delegation standing
//! ([`Vault::capability_slip_id_is_live_in_txn`]). Its claims name class
//! `agent`, its holder is a live named agent's PERSON, and its logged verbs
//! admit a read (`read` or the host's `core:read`). A slip with no read verb
//! has no read reach to show as a Grant: an artifact backend's identity is
//! issued with an empty verb set on purpose (`artifact_hosting`), and stays
//! out. An agent definition and a base agent's MACHINE are no named agent.
//!
//! The Scope is the one the authority log holds for the mint. A presented
//! copy may carry narrower caveats its holder added; the log does not know
//! them.
//!
//! The owner's registry lists each such slip whose holder no Grant has ever
//! named, and his `vault.agents.grants.from_slip` converts one by its id
//! ([`Vault::agent_slip_standing_in_txn`]; GRANTLESS-SHAPE Q8/Q9 = A).

use std::collections::BTreeSet;

use oneiron_authority::federation::Scope;

use super::{CommReach, SlipClaims};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The verbs a slip names to read: the Grant spelling and the host's.
const READ_VERBS: [&str; 2] = ["read", "core:read"];

/// One live issued slip of a named agent, as the authority log holds its
/// mint.
#[derive(Debug, Clone)]
pub(crate) struct LiveAgentSlip {
    /// The slip's id.
    pub(crate) slip_id: [u8; 32],
    /// The named agent's PERSON the slip names as its holder.
    pub(crate) holder: EntityId,
    /// The Scope its mint logged.
    pub(crate) scope: Scope,
    /// Its mint's issue time (Unix seconds).
    pub(crate) issued_at: u64,
    /// When it stops (Unix seconds).
    pub(crate) expires_at: u64,
    /// The named secret and repository bounds it carries beside its Scope.
    pub(crate) records: BTreeSet<String>,
    /// The credential-door effectors it names beside its Scope.
    pub(crate) channels: BTreeSet<String>,
    /// Whom its holder may message; `None` is the vault-wide reach.
    pub(crate) comm: Option<CommReach>,
}

/// Where one slip id stands for a conversion to a Grant
/// ([`Vault::agent_slip_standing_in_txn`]).
#[derive(Debug, Clone)]
pub(crate) enum AgentSlipStanding {
    /// The authority fold counts no mint with this id.
    Unknown,
    /// Its mint names no class `agent`, no read verb or no live named
    /// agent's PERSON.
    NotEligible,
    /// It is revoked, expired or no longer stands on its ancestry, Grant,
    /// invitation or delegation.
    NotLive,
    /// A live issued slip of a named agent that admits a read.
    Live(LiveAgentSlip),
}

/// The slip `id` as [`LiveAgentSlip`] when its claims name class `agent`, a
/// read verb and an entity id holder; whether that holder is a live named
/// agent and the slip is live are the caller's checks.
fn agent_slip_from_claims(id: [u8; 32], claims: &SlipClaims) -> Option<LiveAgentSlip> {
    if claims.actor_class.as_deref() != Some("agent")
        || !READ_VERBS
            .iter()
            .any(|verb| claims.scope.verbs.contains(&(*verb).to_owned()))
    {
        return None;
    }
    let holder = EntityId::from_hex(&claims.holder_ref).ok()?;
    Some(LiveAgentSlip {
        slip_id: id,
        holder,
        scope: claims.scope.clone(),
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
        records: claims.records.clone(),
        channels: claims.channels.clone(),
        comm: claims.comm.clone(),
    })
}

impl Vault {
    /// Every live issued slip of a named agent in `txn` whose logged verbs
    /// admit a read, in slip id order (module docs).
    ///
    /// # Errors
    /// A store, fold or clock failure.
    pub(crate) fn live_agent_slips_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<LiveAgentSlip>> {
        let candidates: Vec<LiveAgentSlip> = {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            fold.slips
                .mints
                .iter()
                .filter_map(|(id, mint)| agent_slip_from_claims(*id, &mint.action.claims))
                .collect()
        };
        let mut live = Vec::with_capacity(candidates.len());
        for slip in candidates {
            if self.is_live_named_agent_in_txn(txn, slip.holder)?
                && self.capability_slip_id_is_live_in_txn(txn, &slip.slip_id)?
            {
                live.push(slip);
            }
        }
        Ok(live)
    }

    /// Where the slip `id` stands in `txn` for a conversion to a Grant: the
    /// same checks as [`Self::live_agent_slips_in_txn`], each failure named.
    ///
    /// # Errors
    /// A store, fold or clock failure.
    pub(crate) fn agent_slip_standing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &[u8; 32],
    ) -> Result<AgentSlipStanding> {
        let slip = {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let Some(mint) = fold.slips.mints.get(id) else {
                return Ok(AgentSlipStanding::Unknown);
            };
            agent_slip_from_claims(*id, &mint.action.claims)
        };
        let Some(slip) = slip else {
            return Ok(AgentSlipStanding::NotEligible);
        };
        if !self.is_live_named_agent_in_txn(txn, slip.holder)? {
            return Ok(AgentSlipStanding::NotEligible);
        }
        if !self.capability_slip_id_is_live_in_txn(txn, id)? {
            return Ok(AgentSlipStanding::NotLive);
        }
        Ok(AgentSlipStanding::Live(slip))
    }
}
