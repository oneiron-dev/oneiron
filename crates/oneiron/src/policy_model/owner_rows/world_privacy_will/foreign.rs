//! An agent's change of a world shared from a connected vault (FIX 4702,
//! DEC-0005 fix 11). Such a world follows its owning vault's settings, so
//! the change is an ask to that vault's holders, a tighten and a widen
//! alike: it goes over the Connect pact the world arrived through
//! ([`super::carry`]) and lands at the owning vault's world-privacy door as
//! any agent's request does, so its holders there decide under their own
//! rules. This vault keeps the ask, pending, until their answer comes back.
//! With no live pact naming the world, the agent keeps today's typed
//! refusal.

use crate::authority::{
    AuthorityFold, FederationPactStatus, PolicyRevision, PrivacyDirection, WorldPrivacy,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::federation::{ScopeAxis, ScopeId};
use crate::{EntityId, Vault};

use super::record::{ForeignWorldPrivacyLink, NewRequest, WorldPrivacyRequestKind as Kind};
use super::{WorldPrivacyOutcome, direction_in_txn};

/// An agent's change of a foreign world that no live Connect carries: the
/// foreign-world rule, and why no ask could go.
const NO_CARRIER: &str = "this world follows its owning vault's settings; its holders there \
                          decide, and no live Connect with that vault names this world, so no \
                          ask can reach them";

/// Whether `world` is in the received-foreign id range: a world shared
/// from another vault.
pub(super) fn is_foreign(world: EntityId) -> bool {
    crate::entity_id::is_foreign_world_id_range(world)
}

/// The Active Connect pact a received-foreign `world` arrived through, with
/// the peer that owns it and the world as that peer names it: the pact whose
/// peer's half of the dual-signed ceiling names a world that lands here as
/// `world`. The derivation keys on the peer and its world alone, so one
/// (peer, world) pair lands as `world`. `None` when no live pact names one;
/// a peer half that shares every world names none, since its worlds cannot
/// be listed.
pub(super) fn owning_world_in(
    fold: &AuthorityFold,
    world: EntityId,
) -> Result<Option<ForeignWorldPrivacyLink>> {
    let Some(local) = fold.vault_id else {
        return Ok(None);
    };
    for (pact, state) in &fold.federation_pacts {
        if state.status != FederationPactStatus::Active {
            continue;
        }
        // The peer's half: what it shares with this vault.
        let inbound = if local <= state.peer_vault_id {
            &state.pact_scope.hi_to_lo
        } else {
            &state.pact_scope.lo_to_hi
        };
        let ScopeAxis::Some(worlds) = &inbound.worlds else {
            continue;
        };
        for ScopeId(owned) in worlds {
            let lands = crate::federation::pact_foreign_world(fold, pact, *owned)?
                .is_some_and(|foreign| foreign.entity_id() == world);
            if lands {
                return Ok(Some(ForeignWorldPrivacyLink {
                    pact: bytes_to_hex_lower(pact),
                    vault: bytes_to_hex_lower(&state.peer_vault_id),
                    world: owned.to_hex(),
                    request: None,
                    agent: None,
                    answer: None,
                }));
            }
        }
    }
    Ok(None)
}

impl Vault {
    /// `agent`'s change of `world`, shared from a connected vault: an ask to
    /// its owning vault's holders, and no settings change here. No Grant
    /// here covers another vault's world. The ask waits here as a proposal,
    /// or as an ask when it widens this vault's copy, and this vault's live
    /// owners are told to carry it
    /// ([`Self::export_foreign_world_privacy`]); the owning vault's answer
    /// settles it ([`Self::receive_foreign_world_privacy`]). It carries
    /// `opener_lineage`, as every agent's request does.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`], the foreign-world refusal, when no live
    /// Connect names the world; [`Error::ConcurrentWrite`] when `seen` is
    /// not the copy's current revision.
    pub(super) fn ask_owning_vault(
        &self,
        agent: EntityId,
        opener_lineage: Vec<[u8; 32]>,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyOutcome> {
        self.with_write_txn(|txn| {
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            let Some(owned_by) = owning_world_in(&fold, world)? else {
                return Err(Error::InvalidConfig(NO_CARRIER.to_owned()));
            };
            let (direction, current) = direction_in_txn(self, txn, world, &settings, seen)?;
            let kind = if direction == PrivacyDirection::Widen {
                Kind::WidenAsk
            } else {
                Kind::Proposal
            };
            // This vault's owners carry it: the holders who decide are there.
            let carriers = super::super::authority::owners_in_txn(self, txn)?;
            let request = self.open_world_privacy_request_in_txn(
                txn,
                NewRequest {
                    kind,
                    agent: Some(agent),
                    opener_lineage,
                    author: agent,
                    world,
                    settings,
                    seen: current,
                    holders: carriers,
                    needs: Vec::new(),
                    yes: Vec::new(),
                    grant_omitted: None,
                    owned_by: Some(owned_by),
                    asked_from: None,
                },
            )?;
            Ok(match kind {
                Kind::WidenAsk => WorldPrivacyOutcome::Asked(request),
                Kind::Proposal => WorldPrivacyOutcome::Proposed(request),
            })
        })
    }
}
