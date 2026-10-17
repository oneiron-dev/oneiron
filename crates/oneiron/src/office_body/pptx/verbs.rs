//! `vault.artifacts.body.deck.*`: the deck doors the generic body verbs do
//! not cover, as agent verbs (FIX 2284). The generic rows read, edit, fork,
//! edit a fork of and discard a deck; these review and land a deck fork,
//! project and land an export, and read and record the export gate's oracle
//! receipt. Each binds the facade's actor as the generic rows do. A deck
//! fork merges by a person other than its opener, as an office fork does
//! (CALLS "OF-505 body verbs").

use serde::{Deserialize, Serialize};

use super::{PptxBody, PptxReview};
use crate::blob_artifact::BlobVersionProvenance;
use crate::edge::EdgeActorClass;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::office_body::OfficeBodyExportRecord;
use oneiron_docedit::edit::Preset;
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
use oneiron_docedit::live::{
    ApproveScope, DeckDiff, ExportProfile, Gate, GeometryProps, Landing, LandingReceipt, NodeId,
    NodeKind, NodePayload, OracleReceipt, TextBody,
};

/// `vault.artifacts.body.deck.merge`: land a reviewed deck fork, naming the
/// head the review read. `scope` is the approval it lands under (this fork
/// alone when absent); `landing` merges onto the head, or switches the head
/// to the fork's deck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckForkMergeRequest {
    pub artifact_ref: String,
    pub fork_ref: String,
    pub reviewed_head: Vec<u8>,
    #[serde(default)]
    pub scope: Option<ApproveScope>,
    #[serde(default)]
    pub landing: Option<Landing>,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// `vault.artifacts.body.deck.export`: project the deck at its head, and
/// land it as the artifact's next version when the export gate is open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckExportRequest {
    pub artifact_ref: String,
    pub run_ref: String,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// `vault.artifacts.body.deck.gate`: one export profile's gate (the default
/// profile when absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckGateRequest {
    #[serde(default)]
    pub profile: Option<String>,
}

/// `vault.artifacts.body.deck.oracle`: the deck oracle's receipt for its
/// profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckOracleRequest {
    pub receipt: OracleReceipt,
}

/// One deck node as a reader and an operation's author see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckNodeView {
    pub id: NodeId,
    pub kind: NodeKind,
    /// The slide or group holding it; `None` for a slide.
    pub parent: Option<NodeId>,
    pub name: Option<String>,
    /// Read from the imported package; false for a live-born node.
    pub imported: bool,
    pub geometry: GeometryProps,
    /// The placeholder kind and index, as read.
    pub placeholder: Option<(String, u32)>,
    pub preset: Option<Preset>,
    pub payload: Option<NodePayload>,
    /// A text shape's body, with the paragraph ids `set_text` keeps.
    pub text: Option<TextBody>,
    /// Who made it; `None` for imported content.
    pub made_by: Option<String>,
}

/// `vault.artifacts.body.read` for a deck: every node under the root in tree
/// order (each slide, then its shapes), at `frontier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckBodyView {
    pub frontier: Vec<u8>,
    /// Operations applied since import.
    pub version: u64,
    pub nodes: Vec<DeckNodeView>,
}

/// `vault.artifacts.body.deck.review`: the fork's merge preflight against
/// the live head. A merge names `head` and lands only when `ok`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckReviewView {
    pub head: Vec<u8>,
    pub head_version: u64,
    pub ok: bool,
    pub diff: DeckDiff,
    pub replay_refusals: Vec<String>,
    /// Units the fork touches that the head changed since its base.
    pub stale_units: Vec<NodeId>,
    /// Why the relationship and render evidence could not be attached.
    pub evidence_refusal: Option<String>,
}

/// `vault.artifacts.body.deck.export`: the projection, and the version it
/// landed. Nothing lands while the gate is closed (the projection is a
/// proposal) or when the deck equals its retained package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckExportView {
    pub frontier: Vec<u8>,
    pub profile: String,
    pub projector: String,
    pub authoritative: bool,
    pub noop: bool,
    pub changed_parts: Vec<String>,
    pub record: Option<OfficeBodyExportRecord>,
}

/// `vault.artifacts.body.deck.gate` and `.oracle`: one profile's export
/// gate, open only on a clean all-pass receipt for the current projector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckGateView {
    pub profile: String,
    pub projector: String,
    pub open: bool,
    pub receipt: Option<OracleReceipt>,
}

impl From<PptxBody> for DeckBodyView {
    fn from(body: PptxBody) -> Self {
        let PptxBody {
            mut deck,
            attribution,
            frontier,
            ..
        } = body;
        let nodes = deck
            .descendants(NodeId(0))
            .into_iter()
            .filter_map(|id| {
                let node = deck.nodes.remove(&id)?;
                Some(DeckNodeView {
                    id,
                    kind: node.kind,
                    parent: node.parent.filter(|parent| *parent != NodeId(0)),
                    name: node.name,
                    imported: node.binding.is_some(),
                    geometry: node.geometry,
                    placeholder: node.placeholder,
                    preset: node.preset,
                    payload: node.payload,
                    text: deck.texts.remove(&id),
                    made_by: attribution
                        .created_by
                        .get(&id)
                        .map(|(actor, _)| actor.clone()),
                })
            })
            .collect();
        Self {
            frontier,
            version: deck.version,
            nodes,
        }
    }
}

impl From<PptxReview> for DeckReviewView {
    fn from(review: PptxReview) -> Self {
        Self {
            head: review.head,
            head_version: review.report.head_version,
            ok: review.report.ok,
            diff: review.report.diff,
            replay_refusals: review.report.replay_refusals,
            stale_units: review.stale_units,
            evidence_refusal: review.evidence_refusal,
        }
    }
}

impl From<Gate> for DeckGateView {
    fn from(gate: Gate) -> Self {
        Self {
            open: gate.is_open(),
            profile: gate.profile,
            projector: PROJECTOR_VERSION.to_owned(),
            receipt: gate.receipt,
        }
    }
}

impl Memory<'_> {
    /// `vault.artifacts.body.deck.review`.
    pub fn artifacts_body_deck_review(
        &self,
        input: &crate::office_body::OfficeBodyForkRequest,
    ) -> MemoryResult<DeckReviewView> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        Ok(self.vault().pptx_body_fork_review(&artifact, &fork)?.into())
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
            &input.reviewed_head,
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
        let export = self.vault().export_pptx_body(&artifact)?;
        let record = if export.authoritative && !export.outcome.noop {
            let actor = self.body_actor();
            let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.deck_export")?;
            let provenance = if actor.actor_class() == EdgeActorClass::Human {
                BlobVersionProvenance::UserUpload
            } else {
                BlobVersionProvenance::AgentRun {
                    run_ref: input.run_ref.clone(),
                }
            };
            let version =
                self.vault()
                    .land_pptx_export(&artifact, &export, actor, &made_by, &provenance)?;
            self.vault()
                .office_body_export(&artifact, version.version)?
        } else {
            None
        };
        Ok(DeckExportView {
            frontier: export.frontier,
            profile: export.outcome.key.profile,
            projector: export.outcome.key.projector,
            authoritative: export.authoritative,
            noop: export.outcome.noop,
            changed_parts: export.outcome.changed_parts,
            record,
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
