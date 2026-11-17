//! `vault.research.bind_authoring` (LEARNING-03; ruling LEARN-ROOT Q2 = A):
//! binds the fixed OF-366 claim-authoring campaign to an existing research
//! root, the bind `vault.research.evaluate_split` scores a split under.
//!
//! The engine builds the campaign's config itself
//! ([`CampaignConfig::of366`]) from the caller's three dataset splits and
//! budget line: the arms, the tournament axes, the verdict epsilon and the
//! OF-360 metric pin are the landed ones, so a caller can never name a ruler
//! revision the engine does not carry. The strategy skill must be the
//! active, admitted Workflow revision its pin names. The general binding,
//! its root node and the claim-authoring row land in one write, or none
//! does; a root binds once, by either bind.
//!
//! Admission (LEARN-GRANT = A, LEARN-ROOT Q1 = A): the vault owner, or an
//! agent whose live owner Grant names it and lists this verb and that runs
//! the root's own leased try (the controller rule every research verb
//! keeps). Both are checked before the bind reads anything, and again in its
//! writing snapshot.

use serde::{Deserialize, Serialize};

use super::research::controller_in_txn;
use super::research_root::admit_owner_or_granted_in_txn;
use crate::attempt_queue::AttemptId;
use crate::autoreason_campaign::authoring::{
    ClaimAuthoringBind, ClaimAuthoringSkillPin, bind_claim_authoring_campaign_admitted,
};
use crate::autoreason_campaign::beam_promotion::AuthoringStrategyPin;
use crate::autoreason_campaign::research::{CandidateRef, ResearchBinding};
use crate::autoreason_campaign::{CampaignBudgetLine, CampaignConfig, CampaignSplits};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, MemoryResult};

/// The verb a Grant lists to name the claim-authoring bind: the row's own
/// name.
const BIND_AUTHORING_VERB: &str = "vault.research.bind_authoring";

/// `vault.research.bind_authoring`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBindAuthoringWire {
    /// The campaign's root attempt, as `vault.research.create_root` returned
    /// it.
    pub root: EntityId,
    /// The search, held-out and sealed dataset revisions, pairwise distinct.
    pub splits: CampaignSplits,
    /// The budget lease line the campaign reserves against.
    pub budget: CampaignBudgetLine,
    /// The exact strategy skill revision the campaign runs.
    pub skill: ClaimAuthoringSkillPin,
    /// The incumbent configuration the root node records.
    pub incumbent: CandidateRef,
    /// The selection-policy holder, if not the campaign's default.
    pub holder: Option<String>,
    /// The budget share the campaign spends from, if not the default.
    pub share: Option<String>,
}

/// What a claim-authoring bind wrote.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBindAuthoringReceipt {
    /// The general campaign binding: the root, its run, the OF-360 ruler as
    /// a metric set and the three splits.
    pub binding: ResearchBinding,
    /// The strategy skill revision the campaign is pinned to.
    pub skill: ClaimAuthoringSkillPin,
    /// The pinned authoring behaviour the campaign is evaluated under.
    pub strategy: AuthoringStrategyPin,
}

/// `vault.research.bind_authoring` on the caller's handle.
///
/// # Errors
///
/// FORBIDDEN for a caller that is not the vault owner, or an agent with a
/// live owner Grant listing the verb that runs the root's own leased try;
/// BAD_REQUEST for splits or a budget line the OF-366 config refuses; a
/// strategy skill that is not the active admitted Workflow revision its pin
/// names; every refusal of `vault.research.bind` (a missing root or run, an
/// invalid incumbent, an already-bound root); storage errors.
pub fn research_bind_authoring(
    memory: &Memory<'_>,
    input: ResearchBindAuthoringWire,
) -> MemoryResult<ResearchBindAuthoringReceipt> {
    let root = AttemptId::from_bytes(input.root.as_bytes())?;
    let vault = memory.vault();
    let admit = |txn: &heed::RoTxn<'_>| -> MemoryResult<()> {
        admit_owner_or_granted_in_txn(memory, txn, BIND_AUTHORING_VERB)?;
        controller_in_txn(memory, txn, Some(root)).map(|_| ())
    };
    {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        admit(&txn)?;
    }
    let splits = input.splits;
    let config = CampaignConfig::of366(splits.search, splits.held_out, splits.sealed, input.budget)
        .map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                format!("{BIND_AUTHORING_VERB}: {error}"),
                &["Name three distinct dataset revisions and a budget line with a positive per-step reserve."],
            )
        })?;
    let bind = ClaimAuthoringBind {
        root,
        config,
        skill: input.skill,
        incumbent: input.incumbent,
        holder: input.holder,
        share: input.share,
    };
    let (campaign, binding) =
        bind_claim_authoring_campaign_admitted(vault, bind, vault.now_recorded_at(), admit)?;
    Ok(ResearchBindAuthoringReceipt {
        binding,
        skill: campaign.skill,
        strategy: campaign.strategy,
    })
}
