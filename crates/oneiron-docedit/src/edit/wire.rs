//! Owned wire forms for the deck edit door (ARCH-0077, "Identities" and "The
//! 23 named refusals"): the native edit targets one read of a deck shows, and
//! why a transaction refused, each serde- and schema-capable for an SDK answer.
//!
//! [`DeckInspection`] copies what [`DeckView::read`] reads: every slide part,
//! `p:sldId/@id` and shape `p:cNvPr/@id`, with the content fingerprints a
//! [`super::transaction::StepTarget`] is checked against, duplicates included.
//! Nothing is minted, repaired, collapsed or hashed again here.
//!
//! [`DeckTransactionRefusal`] keeps a [`TransactionError`] by name: the canon
//! refusals (`target_changed`, `ambiguous_anchor`, ...) with the step index
//! and verb they stopped at. A leaf the organ reports only as an error value
//! (a package, XML, deck or picture error) carries that error's own message
//! as its `detail`; the engine's fixed refusal labels travel the same way.

use serde::{Deserialize, Serialize};

use super::EditRefusal;
use super::transaction::{Digest, IdMarks, StepRefusal, TransactionError};
use crate::deck::{Ambiguity, DeckError, DeckView, ShapeKind};
use crate::native_patch::NativeRefusal;
use crate::retained_opc::Package;

/// A deck's native edit targets, as one read of it shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckInspection {
    /// Every slide in presentation order.
    pub slides: Vec<DeckSlideInspection>,
    /// Duplicate identity evidence, reported and never repaired. A step that
    /// names a shape id its slide repeats refuses `ambiguous_anchor`.
    pub ambiguities: Vec<DeckIdentityAmbiguity>,
    /// The native-id high-water marks the deck shows by itself.
    pub marks: IdMarks,
}

/// One slide: the part a step names and the fingerprints read from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckSlideInspection {
    /// The slide part a step's target names.
    pub part: String,
    /// `p:sldId/@id` in the presentation.
    pub sld_id: u32,
    /// `p14:creationId/@val`, when the slide carries one; never minted.
    pub creation_id: Option<u32>,
    /// Hash of the normalized slide element.
    pub content_fingerprint: Digest,
    /// Hash of the slide and every rendering dependency: the revision
    /// `duplicate_slide` expects.
    pub render_fingerprint: Digest,
    /// Every shape in document order, nested group members included.
    pub shapes: Vec<DeckShapeInspection>,
}

/// One shape: its native identity and the content fingerprint an edit of it
/// expects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckShapeInspection {
    pub kind: DeckShapeKind,
    /// `p:cNvPr/@id`, evidence within the slide: a step's `shape`.
    pub id: Option<u32>,
    /// `a16:creationId/@id`, as an uppercase braced GUID.
    pub creation_id: Option<String>,
    pub name: Option<String>,
    /// Indices into the slide's `shapes` of enclosing groups, outermost
    /// first. A structural hint, not identity.
    pub group_path: Vec<usize>,
    /// The fingerprint a step's `expected` names; a different value refuses
    /// `target_changed`.
    pub content_fingerprint: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckShapeKind {
    Shape,
    Picture,
    GraphicFrame,
    Connector,
    Group,
}

/// Duplicate identity evidence. `slide` and `slides` index the inspection's
/// slides; `shapes` index that slide's shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeckIdentityAmbiguity {
    DuplicateSlideCreationId {
        creation_id: u32,
        slides: Vec<usize>,
    },
    /// A native `p:sldId/@id` more than one slide holds; reported, never
    /// repaired.
    DuplicateSlideId { sld_id: u32, slides: Vec<usize> },
    DuplicateShapeId {
        slide: usize,
        id: u32,
        shapes: Vec<usize>,
    },
    DuplicateShapeCreationId {
        slide: usize,
        id: String,
        shapes: Vec<usize>,
    },
}

/// Read `package`'s native edit targets without changing any byte of it.
pub fn inspect_deck(package: &Package) -> Result<DeckInspection, DeckError> {
    DeckView::read(package).map(|view| DeckInspection::of(&view))
}

impl DeckInspection {
    /// The owned copy of one view's identities and fingerprints.
    #[must_use]
    pub fn of(view: &DeckView) -> Self {
        let slides = view
            .slides
            .iter()
            .map(|slide| DeckSlideInspection {
                part: slide.part.clone(),
                sld_id: slide.sld_id,
                creation_id: slide.creation_id,
                content_fingerprint: Digest(slide.content_fingerprint),
                render_fingerprint: Digest(slide.render_fingerprint),
                shapes: slide
                    .shapes
                    .iter()
                    .map(|shape| DeckShapeInspection {
                        kind: shape.kind.into(),
                        id: shape.id,
                        creation_id: shape.creation_id.clone(),
                        name: shape.name.clone(),
                        group_path: shape.group_path.clone(),
                        content_fingerprint: Digest(shape.content_fingerprint),
                    })
                    .collect(),
            })
            .collect();
        Self {
            slides,
            ambiguities: view.ambiguities.iter().map(Into::into).collect(),
            marks: IdMarks::of_deck(view),
        }
    }
}

impl From<ShapeKind> for DeckShapeKind {
    fn from(kind: ShapeKind) -> Self {
        match kind {
            ShapeKind::Shape => Self::Shape,
            ShapeKind::Picture => Self::Picture,
            ShapeKind::GraphicFrame => Self::GraphicFrame,
            ShapeKind::Connector => Self::Connector,
            ShapeKind::Group => Self::Group,
        }
    }
}

impl From<&Ambiguity> for DeckIdentityAmbiguity {
    fn from(ambiguity: &Ambiguity) -> Self {
        match ambiguity {
            Ambiguity::DuplicateSlideCreationId {
                creation_id,
                slides,
            } => Self::DuplicateSlideCreationId {
                creation_id: *creation_id,
                slides: slides.clone(),
            },
            Ambiguity::DuplicateSlideId { sld_id, slides } => Self::DuplicateSlideId {
                sld_id: *sld_id,
                slides: slides.clone(),
            },
            Ambiguity::DuplicateShapeId { slide, id, shapes } => Self::DuplicateShapeId {
                slide: *slide,
                id: *id,
                shapes: shapes.clone(),
            },
            Ambiguity::DuplicateShapeCreationId { slide, id, shapes } => {
                Self::DuplicateShapeCreationId {
                    slide: *slide,
                    id: id.clone(),
                    shapes: shapes.clone(),
                }
            }
        }
    }
}

/// Why a deck transaction did not run, by name. The base is never changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeckTransactionRefusal {
    /// The transaction breaks its closed grammar or one of its bounds.
    Invalid { detail: String },
    /// The base bytes do not hash to the transaction's base.
    BaseChanged,
    /// The package is signed or its metadata cannot be inspected.
    NotEditable,
    /// One step refused; no step's change is kept.
    Step {
        /// The step's index in the transaction, from zero.
        step: usize,
        /// The step's canon verb name.
        verb: String,
        refusal: DeckStepRefusal,
    },
    /// A part changed outside the union of the steps' allowed sets.
    PartDiffOutsideTransaction { part: String },
    /// The package could not be opened or written.
    Package { detail: String },
    /// The deck could not be read.
    Deck { detail: String },
}

/// Why one step refused: a value or structural edit's canon refusal, a
/// table or chart write's refusal, or an unresolved picture asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeckStepRefusal {
    /// The target's content fingerprint is not the one the step expects.
    TargetChanged,
    /// The target names an identity its slide repeats. A connector end's
    /// repeated shape id names the shapes holding it, so the caller can
    /// pick; other anchors name none.
    AmbiguousAnchor {
        detail: String,
        candidates: Vec<DeckAnchorCandidate>,
    },
    AnimatedTextStructureChanged,
    AnimationDependencyUnsupported {
        detail: String,
    },
    NonInvertibleGroupTransform,
    UnrepresentableTransform {
        detail: String,
    },
    /// The shape inherits its transform; declare offset and extent to own it.
    InheritedTransform,
    PartDiffOutsideTransaction {
        part: String,
    },
    /// A byte outside the edit's declared elements changed.
    WriteOutsideTarget {
        part: String,
        why: String,
    },
    TextMapping {
        detail: String,
    },
    /// The named slide or shape is not there.
    Missing {
        detail: String,
    },
    IdSpaceExhausted,
    ReparentUnsupported {
        detail: String,
    },
    /// A slide dependency outside the tested clone policy, by relationship
    /// kind.
    CloneDependencyUnsupported {
        relationship: String,
    },
    ReorderUnsupported {
        detail: String,
    },
    /// A connector is glued to the shape to delete; a cascade unglues it.
    GluedConnector {
        connector: Option<u32>,
    },
    Invalid {
        detail: String,
    },
    Picture {
        detail: String,
    },
    /// The re-read candidate does not show what the edit wrote.
    ReadBack {
        detail: String,
    },
    Package {
        detail: String,
    },
    Xml {
        detail: String,
    },
    Deck {
        detail: String,
    },
    /// A table cell or chart series write refused.
    Native {
        refusal: DeckNativeRefusal,
    },
    /// The picture asset did not resolve or does not match its reference.
    Asset {
        detail: String,
    },
}

/// One shape an ambiguous anchor may mean: its index in the slide's
/// `shapes` as an inspection lists them, its kind, name and creation id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckAnchorCandidate {
    pub shape: usize,
    pub kind: DeckShapeKind,
    pub name: Option<String>,
    pub creation_id: Option<String>,
}

/// Why a table cell or chart series write refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeckNativeRefusal {
    ExternalChartSource {
        detail: String,
    },
    FormulaBackedSeries {
        detail: String,
    },
    AmbiguousChartData {
        detail: String,
    },
    SharedChartData,
    UnsupportedChartFamily {
        detail: String,
    },
    MergedContinuationCell,
    UnsupportedMergeTopology {
        detail: String,
    },
    /// Same-length replacement is the only supported chart write.
    LengthChange {
        have: usize,
        want: usize,
    },
    /// The target is stale or missing.
    Stale {
        detail: String,
    },
    Invalid {
        detail: String,
    },
    CacheMismatch,
    /// A size the part declares that this host cannot hold now (FIX 9165):
    /// a resource floor, never a count limit.
    MemoryFloor {
        detail: String,
        needed: Option<u64>,
        available: Option<u64>,
    },
    OutsideAllowedParts {
        part: String,
    },
    Workbook {
        detail: String,
    },
    Package {
        detail: String,
    },
    Xml {
        detail: String,
    },
}

impl From<&TransactionError> for DeckTransactionRefusal {
    fn from(error: &TransactionError) -> Self {
        match error {
            TransactionError::Invalid(detail) => Self::Invalid {
                detail: detail.clone(),
            },
            TransactionError::BaseChanged => Self::BaseChanged,
            TransactionError::NotEditable => Self::NotEditable,
            TransactionError::Step {
                step,
                verb,
                refusal,
            } => Self::Step {
                step: *step,
                verb: (*verb).to_owned(),
                refusal: refusal.into(),
            },
            TransactionError::PartDiffOutsideTransaction(part) => {
                Self::PartDiffOutsideTransaction { part: part.clone() }
            }
            TransactionError::Package(error) => Self::Package {
                detail: error.to_string(),
            },
            TransactionError::Deck(error) => Self::Deck {
                detail: error.to_string(),
            },
        }
    }
}

impl From<&StepRefusal> for DeckStepRefusal {
    fn from(refusal: &StepRefusal) -> Self {
        match refusal {
            StepRefusal::Edit(refusal) => refusal.into(),
            StepRefusal::Native(refusal) => Self::Native {
                refusal: refusal.into(),
            },
            StepRefusal::Asset(detail) => Self::Asset {
                detail: (*detail).to_owned(),
            },
        }
    }
}

impl From<&EditRefusal> for DeckStepRefusal {
    fn from(refusal: &EditRefusal) -> Self {
        match refusal {
            EditRefusal::TargetChanged => Self::TargetChanged,
            EditRefusal::AmbiguousAnchor(text) => Self::AmbiguousAnchor {
                detail: (*text).to_owned(),
                candidates: Vec::new(),
            },
            EditRefusal::AmbiguousEndpoint { candidates, .. } => Self::AmbiguousAnchor {
                detail: refusal.to_string(),
                candidates: candidates
                    .iter()
                    .map(|candidate| DeckAnchorCandidate {
                        shape: candidate.shape,
                        kind: candidate.kind.into(),
                        name: candidate.name.clone(),
                        creation_id: candidate.creation_id.clone(),
                    })
                    .collect(),
            },
            EditRefusal::AnimatedTextStructureChanged => Self::AnimatedTextStructureChanged,
            EditRefusal::AnimationDependencyUnsupported(text) => {
                Self::AnimationDependencyUnsupported {
                    detail: (*text).to_owned(),
                }
            }
            EditRefusal::NonInvertibleGroupTransform => Self::NonInvertibleGroupTransform,
            EditRefusal::UnrepresentableTransform(text) => Self::UnrepresentableTransform {
                detail: (*text).to_owned(),
            },
            EditRefusal::InheritedTransform => Self::InheritedTransform,
            EditRefusal::PartDiffOutsideTransaction(part) => {
                Self::PartDiffOutsideTransaction { part: part.clone() }
            }
            EditRefusal::WriteOutsideTarget { part, why } => Self::WriteOutsideTarget {
                part: part.clone(),
                why: (*why).to_owned(),
            },
            EditRefusal::TextMapping(text) => Self::TextMapping {
                detail: (*text).to_owned(),
            },
            EditRefusal::Missing(text) => Self::Missing {
                detail: (*text).to_owned(),
            },
            EditRefusal::IdSpaceExhausted => Self::IdSpaceExhausted,
            EditRefusal::ReparentUnsupported(text) => Self::ReparentUnsupported {
                detail: (*text).to_owned(),
            },
            EditRefusal::CloneDependencyUnsupported(relationship) => {
                Self::CloneDependencyUnsupported {
                    relationship: relationship.clone(),
                }
            }
            EditRefusal::ReorderUnsupported(text) => Self::ReorderUnsupported {
                detail: (*text).to_owned(),
            },
            EditRefusal::GluedConnector(connector) => Self::GluedConnector {
                connector: *connector,
            },
            EditRefusal::Invalid(text) => Self::Invalid {
                detail: (*text).to_owned(),
            },
            EditRefusal::Picture(error) => Self::Picture {
                detail: error.to_string(),
            },
            EditRefusal::ReadBack(text) => Self::ReadBack {
                detail: (*text).to_owned(),
            },
            EditRefusal::Package(error) => Self::Package {
                detail: error.to_string(),
            },
            EditRefusal::Xml(error) => Self::Xml {
                detail: error.to_string(),
            },
            EditRefusal::Deck(error) => Self::Deck {
                detail: error.to_string(),
            },
        }
    }
}

impl From<&NativeRefusal> for DeckNativeRefusal {
    fn from(refusal: &NativeRefusal) -> Self {
        match refusal {
            NativeRefusal::ExternalChartSource(text) => Self::ExternalChartSource {
                detail: (*text).to_owned(),
            },
            NativeRefusal::FormulaBackedSeries(text) => Self::FormulaBackedSeries {
                detail: (*text).to_owned(),
            },
            NativeRefusal::AmbiguousChartData(text) => Self::AmbiguousChartData {
                detail: (*text).to_owned(),
            },
            NativeRefusal::SharedChartData => Self::SharedChartData,
            NativeRefusal::UnsupportedChartFamily(text) => Self::UnsupportedChartFamily {
                detail: (*text).to_owned(),
            },
            NativeRefusal::MergedContinuationCell => Self::MergedContinuationCell,
            NativeRefusal::UnsupportedMergeTopology(text) => Self::UnsupportedMergeTopology {
                detail: (*text).to_owned(),
            },
            NativeRefusal::LengthChange { have, want } => Self::LengthChange {
                have: *have,
                want: *want,
            },
            NativeRefusal::Stale(text) => Self::Stale {
                detail: (*text).to_owned(),
            },
            NativeRefusal::Invalid(text) => Self::Invalid {
                detail: (*text).to_owned(),
            },
            NativeRefusal::CacheMismatch => Self::CacheMismatch,
            NativeRefusal::MemoryFloor {
                reason,
                needed,
                available,
            } => Self::MemoryFloor {
                detail: (*reason).to_owned(),
                needed: *needed,
                available: *available,
            },
            NativeRefusal::OutsideAllowedParts(part) => {
                Self::OutsideAllowedParts { part: part.clone() }
            }
            NativeRefusal::Workbook(error) => Self::Workbook {
                detail: error.to_string(),
            },
            NativeRefusal::Package(error) => Self::Package {
                detail: error.to_string(),
            },
            NativeRefusal::Xml(error) => Self::Xml {
                detail: error.to_string(),
            },
        }
    }
}
