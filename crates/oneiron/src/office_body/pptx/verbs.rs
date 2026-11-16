//! `vault.artifacts.body.deck.*`: the deck doors the generic body verbs do
//! not cover, as agent verbs (FIX 2284). The generic rows read, edit, fork,
//! edit a fork of and discard a deck; these review and land a deck fork,
//! project and land an export (or hold a closed-gate one for Keep), and read
//! and record the export gate's oracle receipt. Each binds the facade's actor as the generic rows do. A deck
//! fork merges by a person other than its opener, as an office fork does
//! (CALLS "OF-505 body verbs").

use serde::{Deserialize, Serialize};

use super::{PptxBody, PptxReview};
use crate::blob_artifact::{BlobVersionProvenance, VersionReconciliation};
use crate::edge::EdgeActorClass;
use crate::edit_settle::PendingProposalView;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::office_body::OfficeBodyExportRecord;
use oneiron_docedit::edit::Preset;
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
use oneiron_docedit::live::{
    ApproveScope, DeckDiff, ExportProfile, Gate, GeometryProps, Landing, LandingReceipt, NodeId,
    NodeKind, NodePayload, OracleReceipt, TextBody, effect_receipt,
};

#[doc(hidden)]
pub use oneiron_verb_wire::office_body::pptx::verbs::{
    DeckExportRequest, DeckForkMergeRequest, DeckGateRequest, DeckOracleRequest,
};

#[doc(hidden)]
pub use oneiron_records::office_body::pptx::verbs::{
    DeckBodyView, DeckGateView, DeckNodeView, DeckReviewView,
};

/// `vault.artifacts.body.deck.export`: the projection, and the version it
/// landed. Nothing lands while the gate is closed (the projection is a
/// proposal, waiting unless the deck equals its retained package) or when
/// the deck equals its retained package and that package is the artifact's
/// head.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeckExportView {
    pub frontier: Vec<u8>,
    pub profile: String,
    pub projector: String,
    pub authoritative: bool,
    pub noop: bool,
    pub changed_parts: Vec<String>,
    /// What the projection did beyond its writes, as its receipt names it:
    /// a preset over custom or inherited geometry, and each edit done
    /// PowerPoint's way where the deck once refused it (a chart type
    /// change, data embedded, SmartArt text, held media, a fitted table).
    pub effects: Vec<String>,
    pub record: Option<OfficeBodyExportRecord>,
    /// A closed-gate projection waiting beside the artifact for Keep under
    /// the request's run ref; `None` when it landed or changed nothing.
    pub proposed: Option<PendingProposalView>,
    /// The export landed while the artifact's head was a version the deck
    /// was not bound to: it forked from the deck's version, and that head
    /// stays beside it as its own version (FIX 2700). `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation: Option<VersionReconciliation>,
}

/// Whether a closed-gate export waits as a proposal for Keep (CALLS
/// "OF-510 closed-gate deck export"); otherwise its bytes are dropped.
const CLOSED_GATE_EXPORT_WAITS: bool = true;

impl Memory<'_> {
    /// `vault.artifacts.body.deck.review`.
    pub fn artifacts_body_deck_review(
        &self,
        input: &crate::office_body::OfficeBodyForkRequest,
    ) -> MemoryResult<DeckReviewView> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        let review: DeckReviewView = self.vault().pptx_body_fork_review(&artifact, &fork)?.into();
        self.lifted_body_view(&artifact, review)
    }

    /// `vault.artifacts.body.deck.merge`: a person lands a reviewed deck
    /// fork. A machine actor's merge is refused until office forks settle
    /// through the consent rung.
    pub fn artifacts_body_deck_merge(
        &self,
        input: &DeckForkMergeRequest,
    ) -> MemoryResult<LandingReceipt> {
        let actor = self.body_actor();
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "a person merges an office body fork",
                &["Office forks do not settle through the consent rung yet."],
            ));
        }
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.deck_merge")?;
        let scope = input
            .scope
            .clone()
            .unwrap_or_else(|| ApproveScope::OneItem(fork.to_hex()));
        Ok(self.vault().merge_pptx_body_fork(
            &artifact,
            &fork,
            (&input.reviewed_head, &input.reviewed_fork),
            actor,
            &made_by,
            scope,
            input.landing.unwrap_or(Landing::Merge),
        )?)
    }

    /// `vault.artifacts.body.deck.export`: project the deck; land it when the
    /// gate is open and the projection changes the package.
    pub fn artifacts_body_deck_export(
        &self,
        input: &DeckExportRequest,
    ) -> MemoryResult<DeckExportView> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let export = self.vault().export_pptx_body(&artifact, input.graphics)?;
        // With the gate open an unchanged deck still lands when the head is a
        // version that landed outside it (FIX 2700): the head becomes the
        // deck's, and that version stays beside it.
        let lands = export.authoritative
            && (!export.outcome.noop
                || self
                    .vault()
                    .blob_artifact_head(&artifact)?
                    .is_some_and(|head| head.version != export.base_version));
        let mut reconciliation = None;
        let record = if lands {
            let actor = self.body_actor();
            let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.deck_export")?;
            let provenance = if actor.actor_class() == EdgeActorClass::Human {
                BlobVersionProvenance::UserUpload
            } else {
                BlobVersionProvenance::AgentRun {
                    run_ref: input.run_ref.clone(),
                }
            };
            let (version, reconciled) =
                self.vault()
                    .land_pptx_export(&artifact, &export, actor, &made_by, &provenance)?;
            reconciliation = reconciled;
            self.vault()
                .office_body_export(&artifact, version.version)?
        } else {
            None
        };
        let proposed = if CLOSED_GATE_EXPORT_WAITS && !export.authoritative && !export.outcome.noop
        {
            let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.deck_export")?;
            // A named envelope is admitted through this handle's lane as it
            // waits (FIX 1229); the body's own names only its writer.
            let named = input.made_by.as_ref().is_some_and(|value| !value.is_null());
            Some(self.vault().propose_pptx_export(
                &artifact,
                &export,
                &input.run_ref,
                (self.body_actor(), &made_by),
                self.made_by_reader(named.then_some(&made_by))?,
            )?)
        } else {
            None
        };
        Ok(DeckExportView {
            frontier: export.frontier,
            profile: export.outcome.key.profile,
            projector: export.outcome.key.projector,
            authoritative: export.authoritative,
            noop: export.outcome.noop,
            effects: export.outcome.effects.iter().map(effect_receipt).collect(),
            changed_parts: export.outcome.changed_parts,
            record,
            proposed,
            reconciliation,
        })
    }

    /// `vault.artifacts.body.deck.gate`.
    pub fn artifacts_body_deck_gate(&self, input: &DeckGateRequest) -> MemoryResult<DeckGateView> {
        let profile = input
            .profile
            .clone()
            .unwrap_or_else(|| ExportProfile::default().name);
        Ok(self.vault().pptx_export_gate(&profile)?.into())
    }

    /// `vault.artifacts.body.deck.oracle`: record the receipt, replacing the
    /// profile's earlier one; the gate as it stands after.
    pub fn artifacts_body_deck_oracle(
        &self,
        input: &DeckOracleRequest,
    ) -> MemoryResult<DeckGateView> {
        self.vault()
            .record_pptx_oracle_receipt(&input.receipt, self.body_actor())?;
        Ok(self
            .vault()
            .pptx_export_gate(&input.receipt.profile)?
            .into())
    }
}
