//! The live deck body (ARCH-0077, "Multiplayer: the target body shape";
//! OF-510), built last in the deck chain.
//!
//! One deck is one collaborative document. This module owns the format-level
//! model that document carries: a deck/shape tree with model [`NodeId`]s
//! kept separate from native `p:cNvPr/@id` evidence, one rich-text body per
//! text shape, stamped operations that each name their actor, a rebuildable
//! attribution index, three-way fork diffs with a merge preflight, and the
//! deterministic export projector back to pptx over the retained package.
//!
//! The engine binds this model to a Loro document (one per deck entity) and
//! to the Grant; nothing here decides authority. Until the eight-step
//! import-then-export check passes on the oracle ([`deck_export::Gate`]),
//! blob versions remain authoritative and this body is a proposal surface.
pub mod deck_export;
pub mod pptx;

pub use deck_export::{
    ExportKey, ExportOutcome, ExportProfile, Gate, HeldAssets, OracleReceipt, RoundtripReport,
    StepOutcome, attach_evidence, project, relationship_changes, roundtrip_check,
};
pub use pptx::{
    ApproveScope, AttributionIndex, ChangeKind, ChartKind, ChartSeries, Conflict, ConnectorEnd,
    DeckDiff, DeckFork, DeckNode, DeckOp, GeometryProps, Landing, LandingReceipt, LiveDeck,
    NodeBinding, NodeId, NodeKind, NodePayload, Paragraph, PreflightReport, RelationshipChange,
    RenderPair, RenderSide, Run, SlideRender, StampedOp, TextBody, diff, land, preflight,
};

use crate::deck::DeckError;
use crate::edit::EditRefusal;
use crate::native_patch::NativeRefusal;
use crate::retained_opc;

/// Why a live-deck operation, landing or export did not happen.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LiveError {
    #[error(transparent)]
    Deck(#[from] DeckError),
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Edit(#[from] EditRefusal),
    /// A live-born table or chart the native writer refused.
    #[error(transparent)]
    Native(#[from] NativeRefusal),
    #[error("invalid live deck operation: {0}")]
    Invalid(&'static str),
    #[error("unknown node")]
    UnknownNode,
    /// A group was asked to contain a slide, or a slide to leave the root.
    #[error("tree shape refused: {0}")]
    TreeShape(&'static str),
    /// The fork's proposer (or its lineage) tried to settle its own proposal.
    #[error("the proposer never settles its own proposal")]
    SelfSettle,
    /// The head advanced past the version the preflight ran against.
    #[error("the head advanced since preflight; repeat the preflight")]
    HeadAdvanced,
    /// Live nodes with no retained binding cannot be projected yet.
    #[error("nodes without a retained binding: {0:?}")]
    UnboundNodes(Vec<NodeId>),
    #[error("live deck encoding: {0}")]
    Encoding(String),
}
