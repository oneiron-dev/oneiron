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

use oneiron_authority::federation::Scope;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The verbs a slip names to read: the Grant spelling and the host's.
const READ_VERBS: [&str; 2] = ["read", "core:read"];

/// One live issued slip of a named agent, as the authority log holds its
/// mint.
#[derive(Debug, Clone)]
pub(crate) struct LiveAgentSlip {
    /// The named agent's PERSON the slip names as its holder.
    pub(crate) holder: EntityId,
    /// The Scope its mint logged.
    pub(crate) scope: Scope,
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
        let candidates: Vec<([u8; 32], LiveAgentSlip)> = {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            fold.slips
                .mints
                .iter()
                .filter(|(_, mint)| {
                    let claims = &mint.action.claims;
                    claims.actor_class.as_deref() == Some("agent")
                        && READ_VERBS
                            .iter()
                            .any(|verb| claims.scope.verbs.contains(&(*verb).to_owned()))
                })
                .filter_map(|(id, mint)| {
                    let claims = &mint.action.claims;
                    let holder = EntityId::from_hex(&claims.holder_ref).ok()?;
                    Some((
                        *id,
                        LiveAgentSlip {
                            holder,
                            scope: claims.scope.clone(),
                        },
                    ))
                })
                .collect()
        };
        let mut live = Vec::with_capacity(candidates.len());
        for (id, slip) in candidates {
            if self.is_live_named_agent_in_txn(txn, slip.holder)?
                && self.capability_slip_id_is_live_in_txn(txn, &id)?
            {
                live.push(slip);
            }
        }
        Ok(live)
    }
}
