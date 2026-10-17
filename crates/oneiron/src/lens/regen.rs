//! Enacting a regeneration outcome through the lens lifecycle (OF-250).
//!
//! [`crate::Vault::regenerate_lens_on_upgrade`] only decides: it returns a
//! [`LensRegenOutcome`] and performs nothing. This module is the caller
//! that decision path names. It routes the outcome through the doors a
//! hand-authored lens revision already takes — `vault.lenses.propose` and
//! `vault.lenses.activate` — so a regenerated candidate is stored, hashed
//! and selected exactly like any other frozen tree, with no second store
//! and no side channel around the owner's slot decision:
//!
//! - `AutoAdopt` — the candidate reads the same bound data as the
//!   last-good lens the owner already selected, so it is proposed and then
//!   selected for the slot under the owner's proof, naming the active lens
//!   it replaces. If the slot moved in between, activation refuses and
//!   the candidate stays a plain proposal.
//! - `NeedsHumanStamp` — the candidate is proposed and nothing more. The
//!   last-good lens stays selected; the owner selects the candidate (or
//!   not) through `vault.lenses.activate`.
//! - `RolledBack` — nothing is stored. The last-good lens stays selected.
//!
//! The candidate's proposal carries the stored intent of the lens it was
//! regenerated from, so the next upgrade reruns the same authored prompt.

use super::proposal::invalid_state;
use super::{
    LensActivateRequest, LensEvaluatedRevision, LensProposeRequest, LensRegenFailurePhase,
    LensRegenOutcome, LensRegenerator, LensSlot,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};
use crate::receipt::{LensActivationReceipt, LensProposalReceipt};
use crate::{EntityId, Error};

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
        let Some(outcome) =
            self.vault()
                .regenerate_lens_on_upgrade(&active_ref, regenerator, last_good)
        else {
            return Ok(LensRegenEnactment::Current {
                active_ref: active_ref.to_hex(),
            });
        };
        self.lenses_enact_regeneration(owner, slot, pack_content_hash, outcome)
    }

    /// Enact an outcome a host already decided (for example through
    /// [`crate::Vault::regenerate_lens_on_upgrade`]) for `slot`'s active lens.
    pub fn lenses_enact_regeneration(
        &self,
        owner: &AuthenticatedOwner,
        slot: LensSlot,
        pack_content_hash: String,
        outcome: LensRegenOutcome,
    ) -> MemoryResult<LensRegenEnactment> {
        let (active_ref, active_lens) = self.active_lens_for(&slot)?;
        // Where the outcome still carries its last-good revision, it must
        // be the lens the slot selects now; a stale outcome enacts nothing.
        // `AutoAdopt` carries only its candidate, so that lane rests on the
        // host having decided against this slot's active lens, and on the
        // activation below naming `active_ref` as what it replaces.
        if !matches!(outcome, LensRegenOutcome::AutoAdopt { .. })
            && outcome.active_revision().lens() != &active_lens
        {
            return Err(invalid_state(
                "the regeneration outcome was decided against a lens the slot no longer selects",
                "Regenerate against the slot's active lens and enact that outcome.",
            ));
        }
        let (candidate, auto_adopt) = match outcome {
            LensRegenOutcome::RolledBack { failure, .. } => {
                return Ok(LensRegenEnactment::RolledBack {
                    active_ref: active_ref.to_hex(),
                    phase: failure.phase(),
                    message: failure.message().to_owned(),
                });
            }
            LensRegenOutcome::AutoAdopt { candidate, .. } => (candidate.into_lens(), true),
            LensRegenOutcome::NeedsHumanStamp { candidate, .. } => {
                ((*candidate).into_lens(), false)
            }
        };
        let intent = self.vault().get_lens_intent(&active_ref)?.ok_or_else(|| {
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
        })?;
        if !auto_adopt {
            return Ok(LensRegenEnactment::ProposedForStamp {
                proposal,
                active_ref: active_ref.to_hex(),
            });
        }
        let activation = self.vault().activate_lens(
            owner,
            LensActivateRequest {
                lens_ref: proposal.lens_ref.clone(),
                compiled_hash: proposal.compiled_hash.clone(),
                expected_active_ref: Some(active_ref.to_hex()),
            },
        )?;
        Ok(LensRegenEnactment::AutoAdopted {
            proposal,
            activation,
        })
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
    outcome: LensRegenOutcome,
) -> MemoryResult<LensRegenEnactment> {
    let owner = memory.embedded_owner("vault.lenses.activate")?;
    memory.lenses_enact_regeneration(&owner, slot, pack_content_hash, outcome)
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
