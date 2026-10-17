//! The live deck body bound to a deck entity (OF-510; ARCH-0077
//! "Multiplayer", ARCH-0075 section 4).
//!
//! One deck entity owns one Loro document (`office_body`, schema
//! `office.pptx.v1`): the format-level model from `oneiron-docedit` (deck/shape
//! tree, one rich-text body per text shape) plus its stamped operation log,
//! from which the attribution index rebuilds. [`DeckBody`] is a read of that
//! document at one frontier, never a second copy: humans edit it live through
//! [`Vault::edit_pptx_body`], machine work arrives as a fork reviewed as a
//! three-way diff with a merge preflight and lands only through a settler who
//! is not the proposer ([`Vault::merge_pptx_body_fork`]).
//!
//! The retained pptx package stays the blob version beside the body. Until
//! the eight-step gate opens for the export profile, blob versions remain
//! authoritative and an export is a proposal artifact, never the head.

use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use oneiron_docedit::live::{
    AttributionIndex, DeckFork, LiveDeck, LiveError, NodeId, PreflightReport, StampedOp, preflight,
};
use serde::{Deserialize, Serialize};

fn live_error(error: LiveError) -> Error {
    crate::office_body::live_refused(error)
}

/// One deck entity's live body as its Loro document holds it at `frontier`.
#[derive(Debug, Clone)]
pub struct DeckBody {
    pub entity: EntityId,
    pub deck: LiveDeck,
    pub log: Vec<StampedOp>,
    pub frontier: Vec<u8>,
}

/// One export of the live body, and whether it may act as the truth.
pub type DeckExport = crate::office_body::PptxExport;

impl Vault {
    /// The deck entity's live body at its head, or at an earlier frontier
    /// `at` of its history.
    pub fn deck_body(&self, entity: &EntityId, at: Option<&[u8]>) -> Result<DeckBody> {
        let body = self.read_pptx_body(entity, at)?;
        Ok(DeckBody {
            entity: *entity,
            deck: body.deck,
            log: body.log,
            frontier: body.frontier,
        })
    }
}

impl DeckBody {
    /// Who made each visible thing, rebuilt from the operation log.
    #[must_use]
    pub fn attribution(&self) -> AttributionIndex {
        AttributionIndex::build(&self.deck, &self.log)
    }

    /// Review a fork against this body: the merge preflight plus the units
    /// the body changed under the fork.
    pub fn review(&self, fork: &DeckFork) -> Result<DeckReview> {
        let report = preflight(&self.deck, fork).map_err(live_error)?;
        let stale_units = fork.stale_units(&self.deck);
        Ok(DeckReview {
            report,
            stale_units,
        })
    }

    /// The race rule (ARCH-0075 section 4): while a proposal is pending,
    /// units the head changed under it have their answers withdrawn and,
    /// after a quiet interval, the proposer is woken to re-evaluate them.
    /// The interval is a policy row the caller supplies, never a constant
    /// here. The wake never settles the proposal.
    #[must_use]
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
