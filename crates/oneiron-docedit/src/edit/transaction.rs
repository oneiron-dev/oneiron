//! Deck transactions (ARCH-0077, "Transactions and allowed part changes"):
//! the unit the engine proposes and ARTL settles.
//!
//! A transaction names its base (BLAKE3 of the blob version's bytes), the
//! native-id high-water marks from managed history, a creation-id seed and
//! its ordered steps. Each step is one checked verb: a value edit
//! ([`super::edit`]), a structural edit ([`super::structure_patch`]) or a
//! table cell or chart series write ([`crate::native_patch::native_patch`]),
//! each with its target and the revision the caller read. Running it returns
//! the candidate bytes and a report: every step's changed parts and effects,
//! the actual part diff against the base, the marks after, and one handoff
//! hash binding candidate bytes, base, write set and report. The derived
//! allowed set is the union of the parts each verb's own check admitted, so
//! a part changed outside every step refuses rather than warns.
//!
//! The grammar is closed and versioned: an unknown key refuses. A settlement
//! replays the same transaction over the same base and settles the handoff
//! hash once, or refuses.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{EditRefusal, Effect, FitUnverified, Picture, Target, ValueEdit, Xfrm};
use super::{NewShape, Preset, StructureEdit, edit, structure_patch};
use crate::deck::{DeckError, DeckView};
use crate::design_plan::{AssetKind, Cell};
use crate::graphic::{AssetRecord, GraphicLimits};
use crate::native_patch::{self, NativeEdit, NativeRefusal};
use crate::retained_opc::{self, Editability, Limits, Package};

/// The grammar version a transaction and its report carry.
pub const DECK_TRANSACTION_SCHEMA: u32 = 1;
/// Steps in one transaction.
pub const MAX_STEPS: usize = 256;
const MAX_SEED_BYTES: usize = 256;
const HANDOFF_CONTEXT: &str = "oneiron docedit deck candidate handoff v1";

/// A BLAKE3 digest, written as 64 lowercase hex digits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            let pair = text.get(index * 2..index * 2 + 2)?;
            if pair.bytes().any(|c| c.is_ascii_uppercase()) {
                return None;
            }
            *byte = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).ok_or_else(|| serde::de::Error::custom("not a lowercase hex digest"))
    }
}

/// The wire form is the 64-digit hex string.
impl schemars::JsonSchema for Digest {
    fn schema_name() -> String {
        "Digest".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

/// Native-id high-water marks in managed history: new ids go above them,
/// never only above the ids that survive (ARCH-0077, "Identities").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdMarks {
    /// `p:sldId/@id`.
    #[serde(default)]
    pub slide: u32,
    /// `p:cNvPr/@id`, per slide part.
    #[serde(default)]
    pub shapes: BTreeMap<String, u32>,
}

impl IdMarks {
    /// Whether every mark in `history` is at or below this one.
    #[must_use]
    pub fn covers(&self, history: &Self) -> bool {
        self.slide >= history.slide
            && history
                .shapes
                .iter()
                .all(|(part, mark)| self.shapes.get(part).is_some_and(|own| own >= mark))
    }

    /// The pointwise maximum.
    pub fn join(&mut self, other: &Self) {
        self.slide = self.slide.max(other.slide);
        for (part, mark) in &other.shapes {
            let own = self.shapes.entry(part.clone()).or_default();
            *own = (*own).max(*mark);
        }
    }

    /// The marks a deck shows by itself: its largest slide id and, per slide
    /// part, its largest shape id.
    #[must_use]
    pub fn of_deck(view: &DeckView) -> Self {
        let mut marks = Self::default();
        for slide in &view.slides {
            marks.slide = marks.slide.max(slide.sld_id);
            let top = slide.shapes.iter().filter_map(|shape| shape.id).max();
            let own = marks.shapes.entry(slide.part.clone()).or_default();
            *own = (*own).max(top.unwrap_or(0));
        }
        marks
    }

    fn shape(&self, part: &str) -> u32 {
        self.shapes.get(part).copied().unwrap_or(0)
    }
}

/// A shape as the caller read it: its slide part, `p:cNvPr/@id` and the
/// content fingerprint, which plays the expected revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepTarget {
    pub slide: String,
    pub shape: u32,
    pub expected: Digest,
}

impl StepTarget {
    fn target(&self) -> Target<'_> {
        Target {
            slide: &self.slide,
            shape: self.shape,
            expected: self.expected.0,
        }
    }
}

/// Declared local transform properties, in EMU and 60,000ths of a degree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepXfrm {
    #[serde(default)]
    pub offset: Option<[i64; 2]>,
    #[serde(default)]
    pub extent: Option<[i64; 2]>,
    #[serde(default)]
    pub rotation: Option<i64>,
    #[serde(default)]
    pub flip_h: Option<bool>,
    #[serde(default)]
    pub flip_v: Option<bool>,
}

/// The closed preset set `add_shape` writes, by its OOXML name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StepPreset {
    Rect,
    RoundRect,
    Ellipse,
    Triangle,
    RightArrow,
}

/// A series sequence: its name, categories (or `c:xVal`), or values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepSequence {
    Name,
    Categories,
    Values,
}

/// One chart cell. A missing cell is not zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepCell {
    Missing,
    Number(f64),
    Text(String),
    /// `yyyy-mm-dd`.
    Date(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepAssetKind {
    Factual,
    Illustration,
}

/// A raster asset by its engine identity; the [`Assets`] resolver supplies
/// the admitted record and bytes, which must hash to `hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssetRef {
    pub artifact: String,
    pub version: u64,
    pub hash: Digest,
    pub kind: StepAssetKind,
    /// Alternative text for the placed picture.
    pub description: String,
}

/// One checked verb (ARCH-0077, "Edit in place with passthrough").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DeckStep {
    SetText {
        target: StepTarget,
        text: String,
    },
    ReplaceRunText {
        target: StepTarget,
        paragraph: usize,
        run: usize,
        expected: String,
        text: String,
    },
    SetXfrm {
        target: StepTarget,
        xfrm: StepXfrm,
    },
    MoveInSlideSpace {
        target: StepTarget,
        dx: i64,
        dy: i64,
    },
    SetPicture {
        target: StepTarget,
        asset: AssetRef,
    },
    SetNotes {
        slide: String,
        #[serde(default)]
        expected: Option<String>,
        text: String,
    },
    AddShape {
        slide: String,
        preset: StepPreset,
        name: String,
        offset: [i64; 2],
        extent: [i64; 2],
    },
    DeleteShape {
        target: StepTarget,
        #[serde(default)]
        cascade: bool,
    },
    Reparent {
        target: StepTarget,
        #[serde(default)]
        parent: Option<u32>,
    },
    DuplicateSlide {
        slide: String,
        expected: Digest,
    },
    ReorderSlides {
        order: Vec<u32>,
    },
    SetTableCell {
        slide: String,
        table: u32,
        row: usize,
        col: usize,
        expected: String,
        value: String,
    },
    SetSeriesValues {
        chart: String,
        series: usize,
        sequence: StepSequence,
        values: Vec<StepCell>,
    },
}

impl DeckStep {
    /// The canon verb name.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::SetText { .. } => "set_text",
            Self::ReplaceRunText { .. } => "replace_run_text",
            Self::SetXfrm { .. } => "set_xfrm",
            Self::MoveInSlideSpace { .. } => "move_in_slide_space",
            Self::SetPicture { .. } => "set_picture",
            Self::SetNotes { .. } => "set_notes",
            Self::AddShape { .. } => "add_shape",
            Self::DeleteShape { .. } => "delete_shape",
            Self::Reparent { .. } => "reparent",
            Self::DuplicateSlide { .. } => "duplicate_slide",
            Self::ReorderSlides { .. } => "reorder_slides",
            Self::SetTableCell { .. } => "set_table_cell",
            Self::SetSeriesValues { .. } => "set_series_values",
        }
    }

    /// Whether the step adds, deletes, moves or reorders model nodes rather
    /// than writing values; such steps run their own dependency checks.
    #[must_use]
    pub const fn is_structural(&self) -> bool {
        matches!(
            self,
            Self::AddShape { .. }
                | Self::DeleteShape { .. }
                | Self::Reparent { .. }
                | Self::DuplicateSlide { .. }
                | Self::ReorderSlides { .. }
        )
    }
}

/// One deck transaction: base, marks, seed and ordered steps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeckTransaction {
    pub schema: u32,
    /// BLAKE3 of the base blob version's bytes.
    pub base: Digest,
    #[serde(default)]
    pub marks: IdMarks,
    /// Derives every creation id the steps mint, so a replay mints the same.
    pub seed: String,
    pub steps: Vec<DeckStep>,
}

impl DeckTransaction {
    /// Parse the closed grammar and check its bounds.
    pub fn parse(json: &str) -> Result<Self, TransactionError> {
        let transaction: Self = serde_json::from_str(json)
            .map_err(|error| TransactionError::Invalid(error.to_string()))?;
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.schema != DECK_TRANSACTION_SCHEMA {
            return Err(TransactionError::Invalid("unknown schema".to_owned()));
        }
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err(TransactionError::Invalid("step count".to_owned()));
        }
        if self.seed.trim().is_empty() || self.seed.len() > MAX_SEED_BYTES {
            return Err(TransactionError::Invalid("seed".to_owned()));
        }
        Ok(())
    }

    /// The canonical text the handoff hash and a settlement bind.
    #[must_use]
    pub fn canonical(&self) -> String {
        serde_json::to_string(self).expect("a deck transaction always serializes")
    }
}

/// How the candidate differs from the base, part by part. Untouched parts
/// are counted, not listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartChangeKind {
    Reserialized,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartChange {
    pub part: String,
    pub change: PartChangeKind,
    pub before: Option<Digest>,
    pub after: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepReport {
    pub verb: String,
    /// The parts this step's own check admitted.
    pub changed_parts: Vec<String>,
    pub effects: Vec<Effect>,
    pub fit: Option<FitUnverified>,
}

/// What a run did, as the receipt carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckTransactionReport {
    pub schema: u32,
    pub base: Digest,
    /// BLAKE3 of the candidate bytes.
    pub candidate: Digest,
    pub steps: Vec<StepReport>,
    /// The actual part diff against the base, in base order, then new parts.
    pub parts: Vec<PartChange>,
    pub untouched: usize,
    /// The marks after the run, for managed history.
    pub marks: IdMarks,
    /// Binds candidate bytes, base, write set and this report.
    pub handoff: Digest,
}

impl DeckTransactionReport {
    /// Shapes whose laid-out text changed with no rendered fit proof.
    pub fn fit_unverified(&self) -> impl Iterator<Item = &FitUnverified> {
        self.steps.iter().filter_map(|step| step.fit.as_ref())
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        serde_json::to_string(self).expect("a deck report always serializes")
    }
}

/// Resolves asset references to admitted records and their bytes.
pub trait Assets {
    fn resolve(&self, asset: &AssetRef) -> Option<(AssetRecord, Vec<u8>)>;
}

/// No assets: every `set_picture` refuses.
pub struct NoAssets;

impl Assets for NoAssets {
    fn resolve(&self, _: &AssetRef) -> Option<(AssetRecord, Vec<u8>)> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum StepRefusal {
    #[error(transparent)]
    Edit(#[from] EditRefusal),
    #[error(transparent)]
    Native(#[from] NativeRefusal),
    #[error("asset: {0}")]
    Asset(&'static str),
}

/// Why a transaction did not run. The base is never changed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TransactionError {
    #[error("invalid deck transaction: {0}")]
    Invalid(String),
    #[error("the base bytes do not hash to the transaction's base")]
    BaseChanged,
    /// Signed or uninspectable packages are reported, never mutated.
    #[error("the package is signed or its metadata cannot be inspected")]
    NotEditable,
    #[error("step {step} ({verb}): {refusal}")]
    Step {
        step: usize,
        verb: &'static str,
        refusal: StepRefusal,
    },
    #[error("changed part outside the transaction's allowed set: {0}")]
    PartDiffOutsideTransaction(String),
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Deck(#[from] DeckError),
}

/// Run one transaction over `base` under `limits`. Returns the candidate
/// bytes and the report; nothing is written anywhere.
pub fn run_transaction(
    base: &[u8],
    transaction: &DeckTransaction,
    limits: Limits,
    assets: &dyn Assets,
) -> Result<(Vec<u8>, DeckTransactionReport), TransactionError> {
    transaction.validate()?;
    if Digest::of(base) != transaction.base {
        return Err(TransactionError::BaseChanged);
    }
    let original = Package::open(base, limits)?;
    if original.editability() != Editability::Unsigned {
        return Err(TransactionError::NotEditable);
    }
    let mut deck = original.clone();
    let mut marks = transaction.marks.clone();
    marks.join(&IdMarks::of_deck(&DeckView::read(&deck)?));
    let mut steps = Vec::with_capacity(transaction.steps.len());
    let mut allowed = BTreeSet::new();
    for (index, step) in transaction.steps.iter().enumerate() {
        let seed = step_seed(&transaction.seed, index);
        let report = apply(&mut deck, step, &mut marks, &seed, assets).map_err(|refusal| {
            TransactionError::Step {
                step: index,
                verb: step.verb(),
                refusal,
            }
        })?;
        allowed.extend(report.changed_parts.iter().cloned());
        steps.push(report);
    }
    let bytes = deck.export()?;
    let candidate = Package::open(&bytes, limits)?;
    let (parts, untouched) = part_diff(&original, &candidate)?;
    if let Some(outside) = parts.iter().find(|change| !allowed.contains(&change.part)) {
        return Err(TransactionError::PartDiffOutsideTransaction(
            outside.part.clone(),
        ));
    }
    marks.join(&IdMarks::of_deck(&DeckView::read(&candidate)?));
    let mut report = DeckTransactionReport {
        schema: DECK_TRANSACTION_SCHEMA,
        base: transaction.base,
        candidate: Digest::of(&bytes),
        steps,
        parts,
        untouched,
        marks,
        handoff: Digest::default(),
    };
    report.handoff = handoff(transaction, &report);
    Ok((bytes, report))
}

/// The checked-candidate handoff: one hash over the transaction (base and
/// write set) and the report (candidate hash, part diff, effects), with the
/// handoff field itself zeroed.
#[must_use]
pub fn handoff(transaction: &DeckTransaction, report: &DeckTransactionReport) -> Digest {
    let mut unbound = report.clone();
    unbound.handoff = Digest::default();
    let mut hasher = blake3::Hasher::new_derive_key(HANDOFF_CONTEXT);
    for field in [transaction.canonical(), unbound.canonical()] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    Digest(*hasher.finalize().as_bytes())
}

fn step_seed(seed: &str, index: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron docedit deck step seed v1");
    hasher.update(&(seed.len() as u64).to_le_bytes());
    hasher.update(seed.as_bytes());
    hasher.update(&(index as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn value(deck: &mut Package, verb: &str, op: &ValueEdit<'_>) -> Result<StepReport, StepRefusal> {
    let report = edit(deck, op)?;
    Ok(StepReport {
        verb: verb.to_owned(),
        changed_parts: report.changed_parts,
        effects: report.effects,
        fit: report.fit.err(),
    })
}

fn structural(
    deck: &mut Package,
    verb: &str,
    op: &StructureEdit<'_>,
) -> Result<StepReport, StepRefusal> {
    let report = structure_patch(deck, op)?;
    Ok(StepReport {
        verb: verb.to_owned(),
        changed_parts: report.changed_parts,
        effects: report.effects,
        fit: None,
    })
}

fn native(deck: &mut Package, verb: &str, op: &NativeEdit<'_>) -> Result<StepReport, StepRefusal> {
    let report = native_patch::native_patch(deck, op)?;
    Ok(StepReport {
        verb: verb.to_owned(),
        changed_parts: report.changed_parts,
        effects: Vec::new(),
        fit: None,
    })
}

fn apply(
    deck: &mut Package,
    step: &DeckStep,
    marks: &mut IdMarks,
    seed: &[u8; 32],
    assets: &dyn Assets,
) -> Result<StepReport, StepRefusal> {
    let verb = step.verb();
    let report = match step {
        DeckStep::SetText { target, text } => value(
            deck,
            verb,
            &ValueEdit::SetText {
                target: target.target(),
                text,
            },
        )?,
        DeckStep::ReplaceRunText {
            target,
            paragraph,
            run,
            expected,
            text,
        } => value(
            deck,
            verb,
            &ValueEdit::ReplaceRunText {
                target: target.target(),
                paragraph: *paragraph,
                run: *run,
                expected,
                text,
            },
        )?,
        DeckStep::SetXfrm { target, xfrm } => value(
            deck,
            verb,
            &ValueEdit::SetXfrm {
                target: target.target(),
                xfrm: Xfrm {
                    offset: xfrm.offset.map(|[x, y]| (x, y)),
                    extent: xfrm.extent.map(|[x, y]| (x, y)),
                    rotation: xfrm.rotation,
                    flip_h: xfrm.flip_h,
                    flip_v: xfrm.flip_v,
                },
            },
        )?,
        DeckStep::MoveInSlideSpace { target, dx, dy } => value(
            deck,
            verb,
            &ValueEdit::MoveInSlideSpace {
                target: target.target(),
                by: (*dx, *dy),
            },
        )?,
        DeckStep::SetPicture { target, asset } => {
            let (record, bytes) = assets
                .resolve(asset)
                .ok_or(StepRefusal::Asset("unresolved asset"))?;
            if Digest::of(&bytes) != asset.hash
                || record.content_hash != asset.hash.0
                || record.artifact != asset.artifact
                || record.version != asset.version
            {
                return Err(StepRefusal::Asset("asset bytes do not match the reference"));
            }
            value(
                deck,
                verb,
                &ValueEdit::SetPicture {
                    target: target.target(),
                    picture: Picture {
                        record: &record,
                        bytes: &bytes,
                        requested: match asset.kind {
                            StepAssetKind::Factual => AssetKind::Factual,
                            StepAssetKind::Illustration => AssetKind::Illustration,
                        },
                        limits: GraphicLimits::default(),
                    },
                },
            )?
        }
        DeckStep::SetNotes {
            slide,
            expected,
            text,
        } => value(
            deck,
            verb,
            &ValueEdit::SetNotes {
                slide,
                expected: expected.as_deref(),
                text,
            },
        )?,
        DeckStep::AddShape {
            slide,
            preset,
            name,
            offset,
            extent,
        } => structural(
            deck,
            verb,
            &StructureEdit::AddShape {
                slide,
                shape: NewShape {
                    preset: match preset {
                        StepPreset::Rect => Preset::Rect,
                        StepPreset::RoundRect => Preset::RoundRect,
                        StepPreset::Ellipse => Preset::Ellipse,
                        StepPreset::Triangle => Preset::Triangle,
                        StepPreset::RightArrow => Preset::RightArrow,
                    },
                    name,
                    offset: (offset[0], offset[1]),
                    extent: (extent[0], extent[1]),
                    high_water: marks.shape(slide),
                    seed,
                },
            },
        )?,
        DeckStep::DeleteShape { target, cascade } => structural(
            deck,
            verb,
            &StructureEdit::DeleteShape {
                target: target.target(),
                cascade: *cascade,
            },
        )?,
        DeckStep::Reparent { target, parent } => structural(
            deck,
            verb,
            &StructureEdit::Reparent {
                target: target.target(),
                parent: *parent,
            },
        )?,
        DeckStep::DuplicateSlide { slide, expected } => structural(
            deck,
            verb,
            &StructureEdit::DuplicateSlide {
                slide,
                expected: expected.0,
                high_water: marks.slide,
                seed,
            },
        )?,
        DeckStep::ReorderSlides { order } => {
            structural(deck, verb, &StructureEdit::ReorderSlides { order })?
        }
        DeckStep::SetTableCell {
            slide,
            table,
            row,
            col,
            expected,
            value: text,
        } => native(
            deck,
            verb,
            &NativeEdit::SetTableCell {
                slide,
                table: *table,
                row: *row,
                col: *col,
                expected,
                value: text,
            },
        )?,
        DeckStep::SetSeriesValues {
            chart,
            series,
            sequence,
            values,
        } => {
            let values: Vec<Cell> = values
                .iter()
                .map(|cell| match cell {
                    StepCell::Missing => Cell::Missing,
                    StepCell::Number(n) => Cell::Number(*n),
                    StepCell::Text(t) => Cell::Text(t.clone()),
                    StepCell::Date(d) => Cell::Date(d.clone()),
                })
                .collect();
            native(
                deck,
                verb,
                &NativeEdit::SetSeries {
                    chart,
                    series: *series,
                    target: match sequence {
                        StepSequence::Name => native_patch::Target::Name,
                        StepSequence::Categories => native_patch::Target::Categories,
                        StepSequence::Values => native_patch::Target::Values,
                    },
                    values: &values,
                },
            )?
        }
    };
    // Every id a step minted moves its mark: a later step allocates above it.
    for effect in &report.effects {
        match effect {
            Effect::ShapeAdded { id, .. } => {
                if let DeckStep::AddShape { slide, .. } = step {
                    let own = marks.shapes.entry(slide.clone()).or_default();
                    *own = (*own).max(*id);
                }
            }
            Effect::SlideAdded { part, sld_id, .. } => {
                marks.slide = marks.slide.max(*sld_id);
                // The copy keeps its source's shape ids, so it starts at the
                // source's mark.
                if let DeckStep::DuplicateSlide { slide, .. } = step {
                    let source = marks.shape(slide);
                    let own = marks.shapes.entry(part.clone()).or_default();
                    *own = (*own).max(source);
                }
            }
            _ => {}
        }
    }
    Ok(report)
}

fn part_diff(
    base: &Package,
    candidate: &Package,
) -> Result<(Vec<PartChange>, usize), retained_opc::Error> {
    let mut changes = Vec::new();
    let mut untouched = 0;
    let names: BTreeSet<&str> = base.names().collect();
    for name in base.names() {
        let before = base.part(name)?.unwrap_or_default();
        match candidate.part(name)? {
            None => changes.push(PartChange {
                part: name.to_owned(),
                change: PartChangeKind::Removed,
                before: Some(Digest::of(&before)),
                after: None,
            }),
            Some(after) if after != before => changes.push(PartChange {
                part: name.to_owned(),
                change: PartChangeKind::Reserialized,
                before: Some(Digest::of(&before)),
                after: Some(Digest::of(&after)),
            }),
            Some(_) => untouched += 1,
        }
    }
    for name in candidate.names() {
        if !names.contains(name) {
            let after = candidate.part(name)?.unwrap_or_default();
            changes.push(PartChange {
                part: name.to_owned(),
                change: PartChangeKind::Added,
                before: None,
                after: Some(Digest::of(&after)),
            });
        }
    }
    Ok((changes, untouched))
}
