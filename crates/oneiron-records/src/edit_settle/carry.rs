//! Moved from `crates/oneiron/src/edit_settle/carry.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_roundtrip::judgment::SheetRowReads;
use oneiron_contracts::entity_id::EntityId;
use oneiron_docedit::pptx_comments::PptxAuthor;
use oneiron_store::model_decision::DecisionQuestion;
use oneiron_store::typed_body::live_pin::LivePin;
use oneiron_store::write_envelope::provenance::made_by::MadeBy;
use oneiron_verb_wire::edit_roundtrip::slides_review::SlideReviewLabels;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;
use std::time::Instant;

/// Why an answer was withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawReason {
    /// What the call read changed: the row's cells or the header row, the
    /// paragraph's text, the file, what the slide shows.
    UnitChanged,
    /// The unit is gone from the head.
    UnitMissing,
    /// Somebody wrote the answer's own cell.
    AnswerCellChanged,
}

/// A withdrawn answer's unit, as its ask names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WithdrawnUnit {
    SheetRow {
        row: u32,
    },
    Paragraph {
        block: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<oneiron_docedit::docx_body::DocxStoryScope>,
    },
    FolderItem {
        file: EntityId,
        row: u32,
    },
    /// A slide by its managed identity, and the shape on it a shape unit
    /// names by creation id.
    Slide {
        part: String,
        sld_id: u32,
        shape: Option<String>,
    },
}

/// One answer withdrawn because its unit changed after it was judged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawnAnswer {
    pub unit: WithdrawnUnit,
    /// What the call read, at the revision the answer was judged against.
    pub judged_on: EntityId,
    pub judged_version: Option<u64>,
    pub judged_hash: [u8; 32],
    /// The version the unit was found changed in; none when only an edit to
    /// the live body, never exported, changed it.
    pub changed_version: Option<u64>,
    /// The live body the answer was judged against, and the one an edit
    /// never exported changed the unit in (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<LivePin>,
    #[serde(default)]
    pub changed_live: Option<LivePin>,
    pub reason: WithdrawReason,
    /// The withdrawn decision, kept for the record; it never lands.
    pub decision: TypedDecision,
    /// When the proposer was woken to re-evaluate it.
    pub woken_at: Option<u64>,
}

/// How the ask a wake asks again was shaped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReaskShape {
    SheetRows {
        sheet: String,
        answer_col: u32,
        reads: SheetRowReads,
        max_count_override: Option<u64>,
    },
    FolderItems {
        sheet: String,
        answer_col: u32,
        max_count_override: Option<u64>,
    },
    Paragraphs {
        author: String,
        labels: SlideReviewLabels,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<oneiron_docedit::docx_body::DocxStoryScope>,
    },
    Slides {
        author: PptxAuthor,
        labels: SlideReviewLabels,
    },
}

/// The answers withdrawn from one held proposal, and its proposer's wake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitWithdrawal {
    pub artifact: EntityId,
    pub proposal_ref: String,
    pub question: DecisionQuestion,
    pub principal: EntityId,
    pub made_by: Option<MadeBy>,
    pub shape: ReaskShape,
    pub answers: Vec<WithdrawnAnswer>,
    /// The versions of the artifact and the files its answers read when the
    /// proposal was last split.
    pub observed: Vec<(EntityId, u64)>,
    /// The live bodies of the artifact and the files, those with one, when
    /// the proposal was last split (FIX 2115).
    #[serde(default)]
    pub observed_live: Vec<(EntityId, LivePin)>,
    /// The proposals each wake asked the changed units in.
    pub reask_refs: Vec<String>,
    /// A failed wake is tried again from here.
    pub retry_at: Option<u64>,
    /// The delta receipt id the withdrawn proposal answered (FIX 11967):
    /// the original PRIMARY stamp, forwarded on re-ask after its pending
    /// row is gone. `None` when no amendment stood behind it.
    pub delta_receipt: Option<String>,
}
