//! The reach's standing outbound grant rows (ARCH-0070 `shape:reach-line`,
//! FIX 2801). A standing outbound grant lets the actor it was minted for act
//! without asking, as the gate's grant match reads it: a grant on a channel,
//! or on the send verb class, covers that actor's sends there. A contact's
//! or a brief's grant is a narrowed path of its own, with values from the
//! grant row only and no generic verdict move (Engine 12:28). A scoped MCP
//! grant is a path of its own: an external tool its actor calls without
//! asking. Capability slips are out of reach by design (Engine 12:28). A
//! grant counts only under the policy frontier it was minted at, so a plan
//! that changes a manifest leaves none counting. Each grant is a standing
//! consent Grant row.
use super::ShapeTarget;
use super::live::ShapeSources;
use super::plan::ShapePlanItem;
use super::reach::{ReachActor, ShapeReachFact, ShapeReachVerdict};
use crate::error::Result;
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope};
use crate::{EntityId, Vault};

/// The channel a scoped MCP grant's path names: the external tool rides the
/// MCP server the grant scopes.
const MCP_CHANNEL: &str = "mcp";

/// The channel a contact grant's narrowed path names: the grant covers sends
/// to one contact on any channel, so the path rides the contact itself.
const CONTACT_CHANNEL: &str = "contact";

/// The channel a brief grant's narrowed path names: the grant covers one
/// brief's verb class, so the path rides the brief itself.
const BRIEF_CHANNEL: &str = "brief";

/// The verb a contact grant's narrowed path carries: sends to the contact it
/// names, as the gate's grant match reads them.
const CONTACT_VERB: &str = "send";

/// One standing outbound grant that counts now, as the reach reads it.
#[derive(Debug, Clone)]
pub(super) struct ReachOutbound {
    pub(super) grant: EntityId,
    /// The actor it lets act, by the principal ref it was minted for.
    pub(super) principal: String,
    pub(super) scope: StandingOutboundGrantScope,
    /// Its stored row's digest, which the frontier pins.
    pub(super) digest: [u8; 32],
}

/// Whether one of `outbound` lets `actor_ref` do `verb` on `channel` without
/// asking, for an effect that names no counterparty and no brief.
pub(super) fn outbound_covers(
    outbound: &[ReachOutbound],
    actor_ref: &str,
    verb: &str,
    channel: &str,
) -> bool {
    outbound.iter().any(|grant| {
        grant.principal == actor_ref && grant.scope.matches_effect(verb, channel, None, None)
    })
}

/// The external tool paths the scoped MCP grants among `outbound` hold: one
/// per grant, for the actor it was minted for, running without asking. A
/// disabled roster actor is not dispatched, so it holds none.
pub(super) fn scoped_mcp_paths(
    outbound: &[ReachOutbound],
    actors: &[ReachActor],
) -> Vec<ShapeReachFact> {
    outbound
        .iter()
        .filter_map(|grant| {
            let StandingOutboundGrantScope::ScopedMcp { server, tool, .. } = &grant.scope else {
                return None;
            };
            let actor = actors
                .iter()
                .find(|actor| actor.entity.to_hex() == grant.principal);
            if actor.is_some_and(|actor| !actor.enabled) {
                return None;
            }
            Some(ShapeReachFact {
                actor: grant.principal.clone(),
                actor_name: actor.map(|actor| actor.agent_id.clone()),
                verb: tool.clone(),
                channel: MCP_CHANNEL.to_owned(),
                sender: server.clone(),
                identity: grant.grant.to_hex(),
                class: None,
                audience: Vec::new(),
                audience_names: Vec::new(),
                verdict: ShapeReachVerdict::Can,
            })
        })
        .collect()
}

/// The narrowed paths the contact and brief grants among `outbound` hold:
/// one per grant, for the actor it was minted for, running without asking
/// (Engine 12:28). Each path's counterparty/brief values come from the grant
/// row's own scope fields only, as the gate's grant match reads them; no
/// generic send or connector verdict moves. A disabled roster actor is not
/// dispatched, so it holds none.
pub(super) fn contact_brief_paths(
    outbound: &[ReachOutbound],
    actors: &[ReachActor],
) -> Vec<ShapeReachFact> {
    outbound
        .iter()
        .filter_map(|grant| {
            let (verb, channel, counterparty, brief) = match &grant.scope {
                StandingOutboundGrantScope::Contact { contact_ref } => (
                    CONTACT_VERB,
                    CONTACT_CHANNEL,
                    Some(contact_ref.as_str()),
                    None,
                ),
                StandingOutboundGrantScope::BriefVerbClass {
                    brief_ref,
                    verb_class,
                } => (
                    verb_class.as_str(),
                    BRIEF_CHANNEL,
                    None,
                    Some(brief_ref.as_str()),
                ),
                _ => return None,
            };
            if !grant
                .scope
                .matches_effect(verb, channel, counterparty, brief)
            {
                return None;
            }
            let actor = actors
                .iter()
                .find(|actor| actor.entity.to_hex() == grant.principal);
            if actor.is_some_and(|actor| !actor.enabled) {
                return None;
            }
            let Some(sender) = counterparty.or(brief) else {
                return None;
            };
            Some(ShapeReachFact {
                actor: grant.principal.clone(),
                actor_name: actor.map(|actor| actor.agent_id.clone()),
                verb: verb.to_owned(),
                channel: channel.to_owned(),
                sender: sender.to_owned(),
                identity: grant.grant.to_hex(),
                class: None,
                audience: Vec::new(),
                audience_names: Vec::new(),
                verdict: ShapeReachVerdict::Can,
            })
        })
        .collect()
}

/// `outbound` once `items` are in place: a plan that changes a manifest
/// moves the policy frontier, and no grant minted at the old one counts.
pub(super) fn outbound_after_plan(outbound: &mut Vec<ReachOutbound>, items: &[ShapePlanItem]) {
    if items
        .iter()
        .any(|item| matches!(item.target, ShapeTarget::Manifest { .. }))
    {
        outbound.clear();
    }
}

impl Vault {
    /// Every standing outbound grant that counts under `policy_frontier`, on
    /// the caller's snapshot. Each grant read is listed in `sources`.
    ///
    /// # Errors
    ///
    /// A read failure or an unencodable grant row.
    pub(super) fn reach_outbound_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        policy_frontier: &[u8; 32],
        sources: &mut ShapeSources,
    ) -> Result<Vec<ReachOutbound>> {
        let mut grants = Vec::new();
        for (_, row) in crate::consent::standing_grant_rows_in_txn(&self.store, txn)? {
            let Some(grant) = StandingOutboundGrant::from_row(&row) else {
                continue;
            };
            sources.list(grant.id);
            if grant.is_active_under_policy(policy_frontier) {
                grants.push(ReachOutbound {
                    grant: grant.id,
                    principal: grant.principal_ref,
                    scope: grant.scope,
                    digest: *blake3::hash(&crate::consent::encode_consent_grant_row(&row)?)
                        .as_bytes(),
                });
            }
        }
        grants.sort_by_key(|grant| *grant.grant.as_bytes());
        Ok(grants)
    }
}
