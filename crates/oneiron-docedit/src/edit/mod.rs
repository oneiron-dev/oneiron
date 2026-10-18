//! Narrow value and text edits in place (ARCH-0077, "Edit in place with
//! passthrough"): `set_text`, `replace_run_text`, `set_run_props`,
//! `set_xfrm`, `move_in_slide_space`, `set_picture`, `set_notes`,
//! `set_preset` and `set_glue`.
//!
//! One edit is one checked operation on a copy of the package. Each verb
//! derives its own allowed part set and its declared elements; the copy lands
//! only when the independent check holds: the actual part diff is inside the
//! allowed set, every byte outside the declared elements is unchanged, and a
//! fresh [`DeckView`] reads the same identities, the same animation index and
//! the written values back. On any refusal the package is left as it was.
//!
//! Edits write own properties and never flatten inherited ones: an inherited
//! transform is not materialised, autofit metrics are kept as written, and a
//! changed text body comes back [`FitUnverified`].
mod check;
pub(crate) mod geometry;
mod media;
mod structure;
#[cfg(test)]
mod tests;
mod text;
pub mod transaction;
mod xfrm;
pub(crate) mod xml;

pub(crate) use structure::recount_slide_text;
pub use structure::{
    ConnectorPreset, NewConnector, NewGroup, NewPicture, NewShape, Preset, StructureEdit,
    StructureReport, structure_patch,
};
pub use transaction::{
    AssetRef, Assets, DeckStep, DeckTransaction, DeckTransactionReport, Digest, IdMarks, NoAssets,
    PartChange, StepRefusal, TransactionError, run_transaction,
};

use crate::deck::{DeckError, DeckView, ShapeView};
use crate::design_plan::AssetKind;
use crate::graphic::{AssetRecord, GraphicError, GraphicLimits};
use crate::ooxml::XmlError;
use crate::retained_opc::{self, Package};

/// The shape an edit addresses: `p:cNvPr/@id` in a slide part, and the
/// content fingerprint the caller read it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    pub slide: &'a str,
    pub shape: u32,
    pub expected: [u8; 32],
}

/// The nine value and text verbs.
#[derive(Debug, Clone, Copy)]
pub enum ValueEdit<'a> {
    /// The whole text body: `\n` separates paragraphs and U+000B is an
    /// `a:br`. Unchanged paragraphs, and the unchanged head and tail of a
    /// changed paragraph, keep their runs, fields, breaks and links; changed
    /// text takes the properties of the run it lands in (see `text.rs`).
    SetText { target: Target<'a>, text: &'a str },
    /// One run's text; `run` counts `a:r` and `a:fld` as [`DeckView`] does.
    ReplaceRunText {
        target: Target<'a>,
        paragraph: usize,
        run: usize,
        expected: &'a str,
        text: &'a str,
    },
    /// Run properties over characters `range` of one paragraph, counted over
    /// its runs and fields as [`DeckView`] reads them; `expected` is that
    /// paragraph's text. Partly covered runs are split at the range's edges.
    SetRunProps {
        target: Target<'a>,
        paragraph: usize,
        range: (usize, usize),
        expected: &'a str,
        props: RunProps<'a>,
    },
    /// Local transform properties; only the declared ones are written.
    SetXfrm { target: Target<'a>, xfrm: Xfrm },
    /// A move by `by` in slide EMU, through the inverse of the composed
    /// parent group transforms.
    MoveInSlideSpace { target: Target<'a>, by: (i64, i64) },
    /// New media for a picture: a new media part and relationship; the
    /// frame, crop and existing media stay as they are.
    SetPicture {
        target: Target<'a>,
        picture: Picture<'a>,
    },
    /// The notes body text, in the same text mapping as `SetText`.
    /// `expected` is the current notes text, `None` when the slide has no
    /// notes slide (one is created over the notes master).
    SetNotes {
        slide: &'a str,
        expected: Option<&'a str>,
        text: &'a str,
    },
    /// A shape's or connector's preset geometry (`a:prstGeom/@prst`): a
    /// [`Preset::name`] for a shape, a [`ConnectorPreset::name`] for a
    /// connector. Its adjust values are dropped; custom geometry refuses.
    SetPreset { target: Target<'a>, preset: &'a str },
    /// A connector's glue: each end the native id of a shape on its slide
    /// and that shape's connection site, or free. Its geometry stays.
    SetGlue {
        target: Target<'a>,
        start: Option<(u32, u32)>,
        end: Option<(u32, u32)>,
    },
}

/// Declared local transform properties, in EMU and 60,000ths of a degree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Xfrm {
    pub offset: Option<(i64, i64)>,
    pub extent: Option<(i64, i64)>,
    pub rotation: Option<i64>,
    pub flip_h: Option<bool>,
    pub flip_v: Option<bool>,
}

/// Declared run properties (`a:rPr`); only the declared ones are written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunProps<'a> {
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    /// Hundredths of a point.
    pub size: Option<u32>,
    /// `a:latin/@typeface`, as written (`+mn-lt` stays a theme reference).
    pub latin: Option<&'a str>,
}

/// A raster asset for `set_picture`, admitted by the ONE-2534 asset checks.
#[derive(Debug, Clone, Copy)]
pub struct Picture<'a> {
    pub record: &'a AssetRecord,
    pub bytes: &'a [u8],
    pub requested: AssetKind,
    pub limits: GraphicLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditReport {
    /// Parts whose exported bytes differ from the input, in package order.
    pub changed_parts: Vec<String>,
    pub effects: Vec<Effect>,
    /// Laid-out text that changed (or a text frame that was resized) has no
    /// rendered fit proof; kept autofit metrics are no new guarantee.
    pub fit: Result<(), FitUnverified>,
}

/// Consequences an edit declares beyond its own write.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// A connector glued to the moved shape keeps its own geometry.
    GluedConnector { connector: Option<u32> },
    /// The picture's previous media relationship is kept, unreferenced by it.
    PreviousMedia { relationship: String },
    /// A new notes slide was created over the notes master.
    NotesCreated { part: String },
    /// A shape was added with this id and minted `a16:creationId`.
    ShapeAdded { id: u32, creation_id: String },
    /// A connector glued to a deleted shape was unglued; its geometry stays.
    Unglued { connector: Option<u32> },
    /// Timing removed with a deleted shape: the `p:cTn` ids it held.
    TimingRemoved { timing_ids: Vec<u32> },
    /// A relationship only the deleted shape used is kept, unreferenced.
    Unreferenced { relationship: String },
    /// A copy of a slide, with its slide id and minted `p14:creationId`.
    SlideAdded {
        part: String,
        sld_id: u32,
        creation_id: Option<u32>,
    },
    /// A dependency the copy owns a clone of.
    PartCloned { from: String, to: String },
    /// A comments relationship of the source the copy does not carry.
    CommentsOmitted { relationship: String },
    /// A custom show that lists the source and is not given the copy.
    NotInCustomShow { show: String },
    /// A slide left the slide list; its part stays, unreachable.
    SlideRemoved { part: String, sld_id: u32 },
    /// One native id of a copied shape (or member) and the id its copy
    /// holds on the destination slide.
    ShapeCopied { from: u32, id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FitUnverified {
    pub part: String,
    pub shape: u32,
}

/// Why an edit did not land. Canon refusals (ARCH-0077) keep their names.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EditRefusal {
    #[error("the target changed since it was read")]
    TargetChanged,
    #[error("ambiguous anchor: {0}")]
    AmbiguousAnchor(&'static str),
    #[error("the edit changes text structure an animation targets")]
    AnimatedTextStructureChanged,
    #[error("animation dependency unsupported: {0}")]
    AnimationDependencyUnsupported(&'static str),
    #[error("a parent group transform cannot be inverted")]
    NonInvertibleGroupTransform,
    #[error("unrepresentable transform: {0}")]
    UnrepresentableTransform(&'static str),
    /// The shape inherits its transform; writing part of it would
    /// materialise the rest.
    #[error("the transform is inherited; declare offset and extent to own it")]
    InheritedTransform,
    #[error("changed part outside the edit's allowed set: {0}")]
    PartDiffOutsideTransaction(String),
    /// A byte outside the edit's declared elements changed.
    #[error("write outside the declared elements in {part}: {why}")]
    WriteOutsideTarget { part: String, why: &'static str },
    /// The text cannot be mapped onto the body without guessing.
    #[error("text mapping refused: {0}")]
    TextMapping(&'static str),
    #[error("missing: {0}")]
    Missing(&'static str),
    /// No native id is left above the high-water mark.
    #[error("the native id space is exhausted")]
    IdSpaceExhausted,
    #[error("reparent unsupported: {0}")]
    ReparentUnsupported(&'static str),
    /// A slide dependency outside the tested clone policy, by relationship
    /// kind.
    #[error("clone dependency unsupported: {0}")]
    CloneDependencyUnsupported(String),
    #[error("reorder unsupported: {0}")]
    ReorderUnsupported(&'static str),
    /// A connector is glued to the shape to delete; a cascade unglues it.
    #[error("a connector is glued to the shape")]
    GluedConnector(Option<u32>),
    #[error("invalid edit: {0}")]
    Invalid(&'static str),
    #[error("picture: {0}")]
    Picture(GraphicError),
    /// The re-read candidate does not show what the edit wrote.
    #[error("the candidate does not read back: {0}")]
    ReadBack(&'static str),
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
    #[error(transparent)]
    Deck(#[from] DeckError),
}

/// What a writer did, for the independent check: the parts it may change
/// and the elements inside them it declared.
struct Written {
    allowed: Vec<String>,
    declared: Vec<check::Declared>,
    relationships: Vec<check::Added>,
    /// New parts and the content type each must be declared with.
    created: Vec<(String, &'static str)>,
    effects: Vec<Effect>,
    fit: Option<FitUnverified>,
}

/// Apply one value or text edit as a single checked operation; on any
/// refusal `deck` is left exactly as it was.
pub fn edit(deck: &mut Package, op: &ValueEdit<'_>) -> Result<EditReport, EditRefusal> {
    let before = DeckView::read(deck)?;
    let mut next = deck.clone();
    let written = match *op {
        ValueEdit::SetText { target, text } => {
            let (index, shape) = locate(&before, &target)?;
            text::set_text(&mut next, &before.slides[index], shape, text)?
        }
        ValueEdit::ReplaceRunText {
            target,
            paragraph,
            run,
            expected,
            text,
        } => {
            let (index, shape) = locate(&before, &target)?;
            let at = (paragraph, run);
            text::replace_run_text(&mut next, &before.slides[index], shape, at, expected, text)?
        }
        ValueEdit::SetRunProps {
            target,
            paragraph,
            range,
            expected,
            props,
        } => {
            let (index, shape) = locate(&before, &target)?;
            let slide = &before.slides[index];
            text::set_run_props(&mut next, slide, shape, paragraph, range, expected, &props)?
        }
        ValueEdit::SetXfrm { target, xfrm } => {
            let (index, shape) = locate(&before, &target)?;
            xfrm::set_xfrm(&mut next, &before.slides[index], shape, &xfrm)?
        }
        ValueEdit::MoveInSlideSpace { target, by } => {
            let (index, shape) = locate(&before, &target)?;
            xfrm::move_in_slide_space(&mut next, &before.slides[index], shape, by)?
        }
        ValueEdit::SetPicture { target, picture } => {
            let (_, shape) = locate(&before, &target)?;
            media::set_picture(&mut next, target.slide, shape, &picture)?
        }
        ValueEdit::SetNotes {
            slide,
            expected,
            text,
        } => {
            if !before.slides.iter().any(|view| view.part == slide) {
                return Err(EditRefusal::Missing("slide"));
            }
            media::set_notes(&mut next, slide, expected, text)?
        }
        ValueEdit::SetPreset { target, preset } => {
            let (index, shape) = locate(&before, &target)?;
            geometry::set_preset(&mut next, &before.slides[index], shape, preset)?
        }
        ValueEdit::SetGlue { target, start, end } => {
            let (index, shape) = locate(&before, &target)?;
            geometry::set_glue(&mut next, &before.slides[index], shape, start, end)?
        }
    };
    let changed = check::verify(deck, &next, &before, op, &written)?;
    *deck = next;
    Ok(EditReport {
        changed_parts: changed,
        effects: written.effects,
        fit: written.fit.map_or(Ok(()), Err),
    })
}

/// The one shape the target names, read with the fingerprint the caller saw.
fn locate<'v>(
    view: &'v DeckView,
    target: &Target<'_>,
) -> Result<(usize, &'v ShapeView), EditRefusal> {
    let index = view
        .slides
        .iter()
        .position(|slide| slide.part == target.slide)
        .ok_or(EditRefusal::Missing("slide"))?;
    let mut shapes = view.slides[index]
        .shapes
        .iter()
        .filter(|shape| shape.id == Some(target.shape));
    let shape = shapes.next().ok_or(EditRefusal::Missing("shape"))?;
    if shapes.next().is_some() {
        return Err(EditRefusal::AmbiguousAnchor(
            "duplicate shape id in the slide",
        ));
    }
    if shape.content_fingerprint != target.expected {
        return Err(EditRefusal::TargetChanged);
    }
    Ok((index, shape))
}
