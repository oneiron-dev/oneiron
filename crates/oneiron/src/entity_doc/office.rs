//! The live deck body bound to a deck entity (OF-510; ARCH-0077
//! "Multiplayer", ARCH-0075 section 4).
//!
//! One deck entity owns one live body: the format-level model from
//! `oneiron-docedit` (deck/shape tree, one rich-text body per text shape,
//! stamped operations) plus its operation log, from which the attribution
//! index rebuilds. Humans edit the body live — those are operations, not
//! proposals. Machine work arrives as a fork against a base version, is
//! reviewed as a three-way diff with a merge preflight, and lands only
//! through a settler who is not the proposer.
//!
//! The retained pptx package stays the blob version beside the body. Until
//! the eight-step gate opens for the export profile, blob versions remain
//! authoritative and an export is a proposal artifact, never the head.
//! Persistence of the body beside the entity's document head rides the
//! shared-office-body storage of OF-505; `snapshot`/`restore` are the
//! bytes that binding carries.

use crate::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use oneiron_docedit::live::{
    ApproveScope, AttributionIndex, DeckFork, DeckOp, ExportOutcome, ExportProfile, Gate, Landing,
    LandingReceipt, LiveDeck, LiveError, NodeId, PreflightReport, StampedOp, land, preflight,
    project,
};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};

fn live_error(error: LiveError) -> Error {
    crate::office_body::live_refused(error)
}

/// One deck entity's live body and its stamped operation log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeckBody {
    pub entity: String,
    pub deck: LiveDeck,
    pub log: Vec<StampedOp>,
}

impl DeckBody {
    /// Import a retained pptx into a live body. Imported content has
    /// unknown authorship; the importer is not recorded as its maker.
    pub fn import(entity: EntityId, pptx_bytes: &[u8], limits: Limits) -> Result<Self> {
        let package =
            Package::open(pptx_bytes, limits).map_err(|error| live_error(error.into()))?;
        let deck = LiveDeck::import(&package).map_err(live_error)?;
        Ok(Self {
            entity: entity.to_hex(),
            deck,
            log: Vec::new(),
        })
    }

    /// The bytes the OF-505 office-body storage carries for this body.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| super::invalid("deck body encoding"))
    }

    pub fn restore(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| super::invalid("deck body decoding"))
    }

    /// A live edit by a person or an admitted peer: an operation stamped
    /// with its actor, never a proposal.
    pub fn apply_live(&mut self, actor: WriteActor, at: u64, op: DeckOp) -> Result<Vec<NodeId>> {
        let stamped = StampedOp {
            made_by: actor.entity_ref().to_hex(),
            at,
            op,
        };
        let affected = self.deck.apply(&stamped).map_err(live_error)?;
        self.log.push(stamped);
        Ok(affected)
    }

    /// Who made each visible thing, rebuilt from the operation log.
    pub fn attribution(&self) -> AttributionIndex {
        AttributionIndex::build(&self.deck, &self.log)
    }

    /// Open a machine fork at the current head. The agent writes the fork,
    /// never the live body.
    pub fn open_fork(
        &self,
        proposal: &str,
        proposer: WriteActor,
        run_root: Option<&str>,
    ) -> DeckFork {
        self.deck
            .fork_at(proposal, &proposer.entity_ref().to_hex(), run_root)
    }

    /// Review a fork against the current head: the merge preflight plus
    /// the units the head changed under the fork.
    pub fn review(&self, fork: &DeckFork) -> Result<DeckReview> {
        let report = preflight(&self.deck, fork).map_err(live_error)?;
        let stale_units = fork.stale_units(&self.deck);
        Ok(DeckReview {
            report,
            stale_units,
        })
    }

    /// Land a reviewed fork. The settler must not be the proposer, the
    /// head must be the preflighted one, and the fork's operations join
    /// the log so attribution survives the landing.
    pub fn land_fork(
        &mut self,
        fork: &DeckFork,
        review: &DeckReview,
        settler: WriteActor,
        scope: ApproveScope,
        landing: Landing,
        automatic: bool,
    ) -> Result<LandingReceipt> {
        let receipt = land(
            &mut self.deck,
            fork,
            &review.report,
            &settler.entity_ref().to_hex(),
            scope,
            landing,
            automatic,
        )
        .map_err(live_error)?;
        self.log.extend(fork.ops.iter().cloned());
        Ok(receipt)
    }

    /// Export pptx on demand over the retained package bytes beside the
    /// body. `authoritative` is true only when the eight-step gate is open
    /// for the profile; before that the blob version stays the truth and
    /// the export is a proposal artifact recording its document version.
    pub fn export(
        &self,
        retained_bytes: &[u8],
        limits: Limits,
        profile: &ExportProfile,
        gate: &Gate,
    ) -> Result<DeckExport> {
        let package =
            Package::open(retained_bytes, limits).map_err(|error| live_error(error.into()))?;
        let outcome = project(&self.deck, &package, &self.entity, profile).map_err(live_error)?;
        Ok(DeckExport {
            authoritative: gate.is_open(),
            outcome,
        })
    }

    /// The race rule (ARCH-0075 section 4): while a proposal is pending,
    /// units the head changed under it have their answers withdrawn and,
    /// after a quiet interval, the proposer is woken to re-evaluate them.
    /// The interval is a policy row the caller supplies, never a constant
    /// here. The wake never settles the proposal.
    pub fn race_wake(&self, fork: &DeckFork, quiet_for_ms: u64) -> Option<ReevalWake> {
        let withdrawn = fork.stale_units(&self.deck);
        if withdrawn.is_empty() {
            return None;
        }
        Some(ReevalWake {
            proposal: fork.proposal.clone(),
            proposer: fork.proposer.clone(),
            withdrawn,
            judged_against: fork.base_version,
            head_version: self.deck.version,
            quiet_for_ms,
        })
    }
}

/// A fork reviewed against the head it must land on.
#[derive(Debug, Clone)]
pub struct DeckReview {
    pub report: PreflightReport,
    /// Fork units the head changed since the base; their answers are the
    /// withdrawn ones, untouched units carry over.
    pub stale_units: Vec<NodeId>,
}

/// One export of the live body, and whether it may act as the truth.
#[derive(Debug, Clone)]
pub struct DeckExport {
    pub authoritative: bool,
    pub outcome: ExportOutcome,
}

/// Wake the proposer to re-evaluate the withdrawn units. Re-evaluation is
/// not acceptance: the Grant or an authorized independent holder answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReevalWake {
    pub proposal: String,
    pub proposer: String,
    pub withdrawn: Vec<NodeId>,
    /// The revision each withdrawn answer was judged against.
    pub judged_against: u64,
    pub head_version: u64,
    /// The quiet interval the policy row asked for, in milliseconds.
    pub quiet_for_ms: u64,
}
