//! Enacting a regeneration outcome through the lens lifecycle (OF-250).
//!
//! [`crate::Vault::regenerate_lens_on_upgrade`] only decides: it returns a
//! [`LensRegenDecision`] (a [`LensRegenOutcome`] and the selection it was
//! made against) and performs nothing. This module is the caller
//! that decision path names. It routes the outcome through the doors a
//! hand-authored lens revision already takes — `vault.lenses.propose` and
//! `vault.lenses.activate` — so a regenerated candidate is stored, hashed
//! and selected exactly like any other frozen tree, with no second store
//! and no side channel around the owner's slot decision:
//!
//! - `AutoAdopt` — the candidate reads the same bound data as the
//!   last-good lens the owner already selected, so it is proposed and then
//!   selected for the slot under the owner's proof, compared and set
//!   against the selection the decision was made against (FIX 9897): its
//!   [`LensRegenDecision::active_ref`] and its outcome's last-good
//!   revision. If the slot moved since, the candidate stays a plain
//!   proposal and the owner's newer selection stays.
//! - `NeedsHumanStamp` — the candidate is proposed and nothing more. The
//!   last-good lens stays selected; the owner selects the candidate (or
//!   not) through `vault.lenses.activate`.
//! - `RolledBack` — nothing is stored. The last-good lens stays selected.
//!
//! The candidate's proposal carries the stored intent of the lens it was
//! regenerated from, so the next upgrade reruns the same authored prompt.
//! A `NeedsHumanStamp` candidate decided against a selection the slot no
//! longer holds is still proposed: the owner may select it, or not.

use super::proposal::invalid_state;
use super::{
    LensActivateRequest, LensEvaluatedRevision, LensProposeRequest, LensRegenFailurePhase,
    LensRegenOutcome, LensRegenerator, LensSlot,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};
use crate::receipt::{LensActivationReceipt, LensProposalReceipt};
use crate::{EntityId, Error};

/// One regeneration decision and the selection it was made against: the
/// slot's active lens when the decision read it (FIX 9897). Its outcome
/// carries that lens's last-good revision.
#[derive(Debug, Clone, PartialEq)]
pub struct LensRegenDecision {
    pub active_ref: EntityId,
    pub outcome: LensRegenOutcome,
}

/// What enacting one [`LensRegenOutcome`] did to its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LensRegenEnactment {
    /// The active lens already targets the live version pair; no
    /// regeneration ran and nothing was stored.
    Current { active_ref: String },
    /// The candidate was proposed and selected for the slot; it is the
    /// lens a render now mounts.
    AutoAdopted {
        proposal: LensProposalReceipt,
        activation: LensActivationReceipt,
    },
    /// The candidate was proposed and waits for the owner's stamp. The
    /// lens at `active_ref` stays selected.
    ProposedForStamp {
        proposal: LensProposalReceipt,
        active_ref: String,
    },
    /// Regeneration failed; nothing was stored and the lens at
    /// `active_ref` stays selected.
    RolledBack {
        active_ref: String,
        phase: LensRegenFailurePhase,
        message: String,
    },
}

impl LensRegenEnactment {
    /// The lens the slot mounts after this enactment.
    #[must_use]
    pub fn mounted_ref(&self) -> &str {
        match self {
            Self::Current { active_ref }
            | Self::ProposedForStamp { active_ref, .. }
            | Self::RolledBack { active_ref, .. } => active_ref,
            Self::AutoAdopted { proposal, .. } => &proposal.lens_ref,
        }
    }
}

impl Memory<'_> {
    /// Run the upgrade decision for `slot`'s active lens and enact its
    /// outcome. `last_good` is the evaluated revision of the lens the slot
    /// currently selects; `pack_content_hash` is the installed pack content
    /// a candidate is compiled against, as `vault.lenses.propose` names it.
    /// `owner` is used only on the auto-adopt lane, to select the candidate
    /// the behavior gate already cleared.
    pub fn lenses_regenerate_and_enact_on_upgrade<R: LensRegenerator + ?Sized>(
        &self,
        owner: &AuthenticatedOwner,
        slot: LensSlot,
        pack_content_hash: String,
        regenerator: &R,
        last_good: LensEvaluatedRevision,
    ) -> MemoryResult<LensRegenEnactment> {
        let (active_ref, _) = self.active_lens_for(&slot)?;
        let Some(decision) =
            self.vault()
                .regenerate_lens_on_upgrade(&active_ref, regenerator, last_good)
        else {
            return Ok(LensRegenEnactment::Current {
                active_ref: active_ref.to_hex(),
            });
        };
        self.lenses_enact_regeneration(owner, slot, pack_content_hash, decision)
    }

    /// Enact a decision a host already made (for example through
    /// [`crate::Vault::regenerate_lens_on_upgrade`]) for `slot`. The
    /// selection the decision was made against is compared and set: a slot
    /// that moved since keeps its newer selection, and the candidate stays a
    /// proposal (FIX 9897).
    pub fn lenses_enact_regeneration(
        &self,
        owner: &AuthenticatedOwner,
        slot: LensSlot,
        pack_content_hash: String,
        decision: LensRegenDecision,
    ) -> MemoryResult<LensRegenEnactment> {
        let LensRegenDecision {
            active_ref: decided_against,
            outcome,
        } = decision;
        let (active_ref, active_lens) = self.active_lens_for(&slot)?;
        let slot_moved =
            active_ref != decided_against || outcome.last_good().lens() != &active_lens;
        let (candidate, auto_adopt) = match outcome {
            LensRegenOutcome::RolledBack { failure, .. } => {
                return Ok(LensRegenEnactment::RolledBack {
                    active_ref: active_ref.to_hex(),
                    phase: failure.phase(),
                    message: failure.message().to_owned(),
                });
            }
            LensRegenOutcome::AutoAdopt { candidate, .. } => (candidate.into_lens(), !slot_moved),
            LensRegenOutcome::NeedsHumanStamp { candidate, .. } => {
                ((*candidate).into_lens(), false)
            }
        };
        // The candidate was regenerated from the decided lens's prompt.
        let intent = self.vault().get_lens_intent(&decided_against)?.ok_or_else(|| {
            invalid_state(
                "the slot's active lens has no stored intent to carry to its candidate",
                "Propose the candidate with its intent through vault.lenses.propose.",
            )
        })?;
        let proposal = self.lenses_propose(LensProposeRequest {
            slot: slot.clone(),
            pack_content_hash,
            compiled: serde_json::to_value(&candidate)
                .map_err(|_| Error::InvalidConfig("regenerated lens did not encode".into()))?,
            intent_prompt: intent.prompt().to_owned(),
            // An upgrade, not a task, ask, run or skill, caused it.
            trigger: None,
        })?;
        if !auto_adopt {
            return Ok(LensRegenEnactment::ProposedForStamp {
                proposal,
                active_ref: active_ref.to_hex(),
            });
        }
        let activated = self.vault().activate_lens(
            owner,
            LensActivateRequest {
                lens_ref: proposal.lens_ref.clone(),
                compiled_hash: proposal.compiled_hash.clone(),
                expected_active_ref: Some(decided_against.to_hex()),
            },
        );
        match activated {
            Ok(activation) => Ok(LensRegenEnactment::AutoAdopted {
                proposal,
                activation,
            }),
            // The slot moved after the check above: its newer selection
            // stays, and the candidate stays a proposal.
            Err(error) => {
                let now = self.vault().active_pack_lens(&slot.pack_name, &slot.skill()?)?;
                match now {
                    Some((now, _)) if now != decided_against => {
                        Ok(LensRegenEnactment::ProposedForStamp {
                            proposal,
                            active_ref: now.to_hex(),
                        })
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// The lens `slot` selects now, rechecked against the live install.
    fn active_lens_for(&self, slot: &LensSlot) -> MemoryResult<(EntityId, super::GeneratedLens)> {
        let skill_id = slot.skill()?;
        self.vault()
            .active_pack_lens(&slot.pack_name, &skill_id)?
            .ok_or_else(|| {
                invalid_state(
                    "that slot has no active lens to regenerate",
                    "Select a lens for the slot through vault.lenses.activate first.",
                )
            })
    }
}

/// [`Memory::lenses_enact_regeneration`] on an embedded handle: the vault's
/// embedded owner's auto-adopt selection.
pub fn enact_lens_regeneration_embedded(
    memory: &Memory<'_>,
    slot: LensSlot,
    pack_content_hash: String,
    decision: LensRegenDecision,
) -> MemoryResult<LensRegenEnactment> {
    let owner = memory.embedded_owner("vault.lenses.activate")?;
    memory.lenses_enact_regeneration(&owner, slot, pack_content_hash, decision)
}

/// [`Memory::lenses_regenerate_and_enact_on_upgrade`] on an embedded handle.
pub fn regenerate_and_enact_lens_embedded<R: LensRegenerator + ?Sized>(
    memory: &Memory<'_>,
    slot: LensSlot,
    pack_content_hash: String,
    regenerator: &R,
    last_good: LensEvaluatedRevision,
) -> MemoryResult<LensRegenEnactment> {
    let owner = memory.embedded_owner("vault.lenses.activate")?;
    memory.lenses_regenerate_and_enact_on_upgrade(
        &owner,
        slot,
        pack_content_hash,
        regenerator,
        last_good,
    )
}
