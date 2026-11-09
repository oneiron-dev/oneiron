//! The owner's opt-out of a system agent's grant (untangle 6.3c; S6-4
//! amended, owner 9 Nov 15:21: "we can make it opt-out, but give a big-ass
//! warning that it might break shit").
//!
//! The owner may narrow or revoke a base agent's Steward grant. Some grants
//! keep the vault working (the Dreamer's: consolidation and recall upkeep),
//! so the vault marks them system-critical, naming the functions each
//! serves. Narrowing a marked grant first returns what breaks and changes
//! nothing; it applies only when the owner confirms that exact list. One
//! warning serves every marked grant. The narrowing is the owner's signed
//! revoke of the old grant and, when any verb stays, his signed mint of the
//! narrower one; a narrowing record keeps the verbs before and after and the
//! breaks he confirmed. The door never widens: a grant back is the owner's
//! own grant ([`Vault::grant_dreamer_weave`] for the Dreamer).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{SYSTEM_AGENT_GRANT, SystemAgentGrantState, standing_steward_verbs_in};
use crate::Vault;
use crate::authority::{ActSurface, AgentGrantAct};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::grant_scope;
use crate::side_table::{self, Named, SideTable};

/// The functions each system-critical grant serves, by the grant.
const SYSTEM_CRITICAL_GRANT: SideTable<EntityId, BTreeSet<SystemFunction>, Named> =
    SideTable::new(&side_table::FEDERATION_SYSTEM_CRITICAL_GRANT);

/// Each narrowing the owner applied, by the agent and the recording time.
const SYSTEM_AGENT_NARROWING: SideTable<(EntityId, u64), SystemAgentNarrowing, Named> =
    SideTable::new(&side_table::FEDERATION_SYSTEM_AGENT_NARROWING);

/// The domain of the confirm token a narrowing hands back.
const CONFIRM_DOMAIN: &str = "oneiron/system-agent-grant-narrowing/v1";

/// One vault function a system agent's grant keeps running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemFunction {
    /// The Dreamer turns new conversations into memory.
    Consolidation,
    /// The Dreamer archives weak, quiet memories so recall stays sharp.
    RecallUpkeep,
    /// The Coach checks how the vault's agents are doing.
    CoachChecks,
    /// The Coach runs the jobs the engine.controls classes tune.
    EngineControlsJobs,
}

impl SystemFunction {
    /// The Steward verbs this function needs: a narrowing that drops any of
    /// them breaks it.
    #[must_use]
    pub const fn needs(self) -> &'static [&'static str] {
        match self {
            Self::Consolidation => &[
                grant_scope::STEWARD_READ_VERB,
                grant_scope::STEWARD_DERIVE_VERB,
            ],
            Self::RecallUpkeep => &[
                grant_scope::STEWARD_READ_VERB,
                grant_scope::STEWARD_ARCHIVE_VERB,
            ],
            Self::CoachChecks => &[grant_scope::STEWARD_READ_VERB],
            Self::EngineControlsJobs => &grant_scope::ENGINE_CONTROLS_VERBS,
        }
    }

    /// What stops, in one plain sentence, for the warning.
    #[must_use]
    pub const fn what_breaks(self) -> &'static str {
        match self {
            Self::Consolidation => {
                "Consolidation stops: new conversations are no longer turned into memory."
            }
            Self::RecallUpkeep => {
                "Recall upkeep stops: weak, quiet memories are no longer archived, so recall gets noisier."
            }
            Self::CoachChecks => {
                "Coach checks stop: the Coach no longer checks how the vault's agents are doing."
            }
            Self::EngineControlsJobs => {
                "Engine-control jobs stop: schedules, budgets and recipes are no longer tuned for you."
            }
        }
    }
}

/// The functions the Dreamer's grant serves: what its rows ran.
pub(super) const DREAMER_FUNCTIONS: [SystemFunction; 2] =
    [SystemFunction::Consolidation, SystemFunction::RecallUpkeep];

/// The functions the Coach's grant serves (6.6): its checks read the vault,
/// and its jobs tune the engine.
pub(super) const COACH_FUNCTIONS: [SystemFunction; 2] = [
    SystemFunction::CoachChecks,
    SystemFunction::EngineControlsJobs,
];

/// The one warning every system-critical narrowing shows.
pub const SYSTEM_AGENT_GRANT_NARROWING_WARNING: &str = "This grant belongs to a system agent that keeps your vault working. Narrowing \
     it stops the functions listed below. Apply it only if you mean to; you can grant it back \
     later.";

/// What the narrowing door did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemAgentGrantNarrowing {
    /// Nothing to narrow: the grant already holds no more than asked, or no
    /// grant stands.
    Unchanged,
    /// Nothing changed: the narrowing breaks `breaks`. Ask again with
    /// `confirm` to apply it.
    ConfirmRequired {
        warning: &'static str,
        breaks: Vec<SystemFunction>,
        confirm: [u8; 32],
    },
    /// Applied. `grant` is the narrower grant, `None` when it was revoked
    /// whole; `breaks` what the owner confirmed.
    Narrowed {
        grant: Option<EntityId>,
        breaks: Vec<SystemFunction>,
    },
}

/// One narrowing the owner applied, as the record keeps it: that he chose
/// it, what the grant held before and after, and the breaks he confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemAgentNarrowing {
    /// The owner who applied it.
    #[serde(with = "crate::serialize::entity_ref")]
    pub owner: EntityId,
    /// The grant his signed revoke took back.
    #[serde(with = "crate::serialize::entity_ref")]
    pub revoked: EntityId,
    /// The narrower grant his signed mint gave; `None` when he revoked it whole.
    #[serde(default, with = "crate::serialize::entity_ref::optional")]
    pub minted: Option<EntityId>,
    /// The verbs the grant held before.
    pub before: BTreeSet<String>,
    /// The verbs it holds after.
    pub after: BTreeSet<String>,
    /// The breaks he confirmed (empty for a grant not marked system-critical).
    pub confirmed: Vec<SystemFunction>,
}

/// The token a confirm must carry: it binds the grant, the verbs kept and
/// the breaks the owner was shown, so a confirm of one list never applies
/// another.
fn confirm_token(grant: EntityId, keep: &BTreeSet<String>, breaks: &[SystemFunction]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CONFIRM_DOMAIN);
    hasher.update(grant.as_bytes());
    for verb in keep {
        hasher.update(verb.as_bytes());
        hasher.update(&[0]);
    }
    hasher.update(&[0xff]);
    for function in breaks {
        hasher.update(&[*function as u8]);
    }
    *hasher.finalize().as_bytes()
}

impl Vault {
    /// Every narrowing the owner applied to base agent `agent`'s grant,
    /// oldest first, with when it was recorded.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn system_agent_narrowings(
        &self,
        agent: EntityId,
    ) -> Result<Vec<(u64, SystemAgentNarrowing)>> {
        let txn = self.store.env.read_txn()?;
        Ok(SYSTEM_AGENT_NARROWING
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|((recorded_for, _), _)| *recorded_for == agent)
            .map(|((_, at), narrowing)| (at, narrowing))
            .collect())
    }

    /// Marks `grant` system-critical for `functions`, in the caller's
    /// writer.
    pub(super) fn mark_system_critical_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
        functions: &[SystemFunction],
    ) -> Result<()> {
        SYSTEM_CRITICAL_GRANT.put(
            &self.store,
            txn,
            &grant,
            &functions.iter().copied().collect(),
        )
    }

    /// Owner act: narrows base agent `agent`'s Steward grant to the verbs in
    /// `keep` (empty revokes it whole). A grant the vault marks
    /// system-critical returns [`SystemAgentGrantNarrowing::ConfirmRequired`]
    /// with what breaks and changes nothing, unless `confirm` is the token
    /// that answer carried; then it applies. The door never widens: a verb
    /// in `keep` the grant does not hold refuses.
    ///
    /// # Errors
    ///
    /// An owner refusal; `InvalidConfig` for a widening or a verb no Steward
    /// holds; a store failure; `AuthorityRefused` when this install cannot
    /// carry the owner's act.
    pub fn narrow_system_agent_grant(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        keep: &BTreeSet<String>,
        confirm: Option<[u8; 32]>,
    ) -> Result<SystemAgentGrantNarrowing> {
        if keep
            .iter()
            .any(|verb| !grant_scope::STEWARD_CEILING_VERBS.contains(&verb.as_str()))
        {
            return Err(Error::InvalidConfig(
                "a Steward grant holds read, derive, archive, delete and the engine.controls classes only"
                    .into(),
            ));
        }
        let narrowing = self.with_write_txn_grouped(|txn| {
            let owner_ref = owner.revalidate_in_txn(self, &*txn)?;
            let Some(SystemAgentGrantState::Minted { grant }) =
                SYSTEM_AGENT_GRANT.get(&self.store, &*txn, &agent)?
            else {
                return Ok(SystemAgentGrantNarrowing::Unchanged);
            };
            let before = standing_steward_verbs_in(&self.store, &*txn, grant, agent)?;
            if before.is_empty() {
                return Ok(SystemAgentGrantNarrowing::Unchanged);
            }
            if !keep.is_subset(&before) {
                return Err(Error::InvalidConfig(
                    "the narrowing door never widens a grant; grant it back instead".into(),
                ));
            }
            if *keep == before {
                return Ok(SystemAgentGrantNarrowing::Unchanged);
            }
            let functions = SYSTEM_CRITICAL_GRANT
                .get(&self.store, &*txn, &grant)?
                .unwrap_or_default();
            let breaks: Vec<SystemFunction> = functions
                .into_iter()
                .filter(|function| {
                    function
                        .needs()
                        .iter()
                        .any(|verb| before.contains(*verb) && !keep.contains(*verb))
                })
                .collect();
            let token = confirm_token(grant, keep, &breaks);
            if !breaks.is_empty() && confirm != Some(token) {
                return Ok(SystemAgentGrantNarrowing::ConfirmRequired {
                    warning: SYSTEM_AGENT_GRANT_NARROWING_WARNING,
                    breaks,
                    confirm: token,
                });
            }
            // The owner's signed revoke of the grant in force, then, when a
            // verb stays, his signed mint of the narrower one.
            let acknowledged_topology =
                crate::identity_topology::acknowledged_grant_seals_in_txn(&self.store, txn, grant)
                    .unwrap_or_default();
            self.append_agent_grant_act_in_txn(
                txn,
                owner,
                ActSurface::ThisInstall,
                AgentGrantAct::Revoke {
                    grant,
                    acknowledged_topology,
                },
            )?;
            self.delete_agent_grant_row_in_txn(txn, grant)?;
            let minted = if keep.is_empty() {
                None
            } else {
                let narrower = self.mint_steward_grant_in_txn(txn, owner, agent, keep.clone())?;
                let marked: Vec<SystemFunction> = SYSTEM_CRITICAL_GRANT
                    .get(&self.store, &*txn, &grant)?
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if !marked.is_empty() {
                    self.mark_system_critical_in_txn(txn, narrower, &marked)?;
                }
                Some(narrower)
            };
            SYSTEM_CRITICAL_GRANT.delete(&self.store, txn, &grant)?;
            SYSTEM_AGENT_GRANT.put(
                &self.store,
                txn,
                &agent,
                &minted.map_or(SystemAgentGrantState::OptedOut, |grant| {
                    SystemAgentGrantState::Minted { grant }
                }),
            )?;
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            SYSTEM_AGENT_NARROWING.put(
                &self.store,
                txn,
                &(agent, at),
                &SystemAgentNarrowing {
                    owner: owner_ref,
                    revoked: grant,
                    minted,
                    before,
                    after: keep.clone(),
                    confirmed: breaks.clone(),
                },
            )?;
            Ok(SystemAgentGrantNarrowing::Narrowed {
                grant: minted,
                breaks,
            })
        })?;
        if matches!(narrowing, SystemAgentGrantNarrowing::Narrowed { .. }) {
            // The fold's rows moved with the grant: a floor this commit moved
            // is judged again at once (FIX 5505).
            self.apply_pending_rebinds_after_commit();
        }
        Ok(narrowing)
    }
}

#[cfg(test)]
mod tests;
