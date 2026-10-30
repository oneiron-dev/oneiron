//! The graphic compiler: an asset a design plan places becomes editable
//! DrawingML shapes (an SVG in the closed subset) or a verified image binding
//! (PNG or JPEG). Nothing is rasterized here: unsupported SVG is refused, and
//! rasterizing is a separate output choice with its own derivation receipt.
//!
//! The binding is checked before the bytes. The engine's asset record must
//! name the plan's handle and media type, its provenance must be complete for
//! its origin, and its bytes must be stored and hash to the recorded content
//! hash. The compiler consumes the engine's asset-use decision; it never
//! decides provenance or authority.

mod asset;
mod drawingml;
mod geometry;
mod path;
mod svg;
#[cfg(test)]
mod tests;

use crate::design_plan::{AssetBinding, AssetKind, MediaType, Rect};
use crate::resource::{CapacityHit, ResourceRefusal, Resources};
use std::collections::BTreeSet;

/// 96 px per inch.
pub const EMU_PER_PX: i64 = 9525;

/// What `compile_graphic` reads for one placed asset.
#[derive(Debug, Clone)]
pub struct GraphicInput<'a> {
    /// The plan's binding for the asset.
    pub binding: &'a AssetBinding,
    /// What the brief asked for.
    pub requested: AssetKind,
    pub record: &'a AssetRecord,
    /// The stored bytes, or `None` while they are not durable: missing bytes
    /// are an incomplete state, never an empty image.
    pub bytes: Option<&'a [u8]>,
    /// The plan's destination for the asset, in slide EMU.
    pub bounds: Rect,
    pub limits: GraphicLimits,
}

/// The engine's record of one asset version, mirrored here because this
/// crate does not depend on the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetRecord {
    /// Engine artifact identity; the plan binding's handle names it.
    pub artifact: String,
    pub version: u64,
    /// BLAKE3 of the version's bytes.
    pub content_hash: [u8; 32],
    pub media: MediaType,
    pub origin: Origin,
    /// Engine provenance references, such as the version's producer claim.
    pub provenance: Vec<String>,
    /// Rights-evidence references, such as a licence claim.
    pub rights: Vec<String>,
    /// Alternative text for the placed object.
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// An asset the person already holds.
    Held,
    /// An image from the web; its licence claim is in `rights`.
    Web,
    /// A stock image; its licence claim is in `rights`.
    Stock,
    /// A generated-image adapter result.
    Generated {
        reviewed: ReviewedRequest,
        receipt: Box<GenerationReceipt>,
    },
    /// A diagram authored in the closed SVG subset.
    Diagram,
}

/// The outbound request a person reviewed before it was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedRequest {
    pub prompt: [u8; 32],
    pub references: BTreeSet<[u8; 32]>,
}

/// What the adapter returned about a generation; `None` is a missing field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GenerationReceipt {
    pub prompt: Option<[u8; 32]>,
    pub references: Option<BTreeSet<[u8; 32]>>,
    /// Model identity and version.
    pub model: Option<String>,
    /// Adapter identity and version.
    pub adapter: Option<String>,
    pub params_hash: Option<[u8; 32]>,
    pub output_hash: Option<[u8; 32]>,
    /// Recorded when the adapter returns one; it promises no reproducibility.
    pub seed: Option<u64>,
}

/// Payload ceilings. Past a byte or pixel one, the asset is refused as a
/// capacity hit naming it ([`GraphicError::Capacity`]), not truncated. The
/// SVG node, depth, segment and fill-edge counts are observations (FIX
/// 8574): the compiler reserves their memory through the operation's port
/// and checkpoints the quadratic fill-rule proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphicLimits {
    pub svg_bytes: usize,
    pub svg_nodes: usize,
    pub svg_depth: usize,
    /// Drawing segments in one graphic: an observation.
    pub segments: usize,
    /// Edges in one filled outline: an observation.
    pub fill_edges: usize,
    pub raster_bytes: usize,
    pub raster_pixels: u64,
}

impl Default for GraphicLimits {
    fn default() -> Self {
        Self {
            svg_bytes: 1 << 20,
            svg_nodes: 10_000,
            svg_depth: 32,
            segments: 20_000,
            fill_edges: 2_048,
            raster_bytes: 50 << 20,
            raster_pixels: 64_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledGraphic {
    pub output: Output,
    pub record: AssetUse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Shapes(Drawing),
    Image(ImageBinding),
}

/// A raster asset whose bytes, type and dimensions were checked; emission
/// writes it as a picture over its media part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBinding {
    pub handle: String,
    pub media: MediaType,
    pub placed: Rect,
}

/// The canon's asset record for one use: identity, evidence, generation,
/// dimensions and description. Emission adds the output NodeId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetUse {
    pub artifact: String,
    pub version: u64,
    pub content_hash: [u8; 32],
    pub provenance: Vec<String>,
    pub rights: Vec<String>,
    pub generated: Option<GenerationReceipt>,
    /// The viewBox, or the image's pixels, at 1px = 9,525 EMU.
    pub original: Extent,
    /// The original scaled uniformly into the destination and centred; no
    /// crop is ever planned.
    pub placed: Rect,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub cx: i64,
    pub cy: i64,
}

/// A compiled SVG: one group of native shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drawing {
    /// The group's child space: the viewBox at 1px = 9,525 EMU. Shape
    /// coordinates are absolute in it.
    pub child: Rect,
    /// Where the group lands in the slide.
    pub placed: Rect,
    /// Source order is z-order.
    pub shapes: Vec<NativeShape>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeShape {
    /// The SVG element's `id`, else its element name.
    pub name: String,
    pub frame: Frame,
    pub geometry: Geometry,
    pub fill: Option<Solid>,
    pub stroke: Option<Stroke>,
}

/// A shape's `a:xfrm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub rect: Rect,
    /// Clockwise, in 60,000ths of a degree.
    pub rot: i32,
    pub flip_v: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Geometry {
    Preset(Preset),
    /// `a:custGeom` paths in frame-local EMU, one path unit per EMU.
    Custom(Vec<PathSpec>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Rect,
    /// `adj` is the corner radius in 100,000ths of the shorter side.
    RoundRect {
        adj: i64,
    },
    Ellipse,
    /// From the frame's top-left to its bottom-right, or bottom-left to
    /// top-right when flipped.
    Line,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSpec {
    pub w: i64,
    pub h: i64,
    pub fill: bool,
    pub stroke: bool,
    pub segments: Vec<Segment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    MoveTo(Pt),
    LineTo(Pt),
    CubicTo(Pt, Pt, Pt),
    QuadTo(Pt, Pt),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pt {
    pub x: i64,
    pub y: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Solid {
    pub rgb: [u8; 3],
    /// Opacity in 1/100,000.
    pub alpha: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stroke {
    /// EMU.
    pub width: i64,
    pub paint: Solid,
    pub cap: Cap,
    pub join: Join,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    Flat,
    Round,
    Square,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    /// `limit` is the miter limit in 1/100,000.
    Miter {
        limit: u32,
    },
    Round,
    Bevel,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraphicError {
    #[error("the asset record does not match the plan's binding")]
    BindingMismatch,
    #[error("the asset has no description")]
    MissingDescription,
    #[error("the asset has no engine provenance")]
    MissingProvenance,
    #[error("a web or stock image needs a licence claim")]
    MissingLicence,
    #[error("a stock or generated image cannot stand in for a requested factual asset")]
    NotFactual,
    #[error("the adapter response is missing {0}")]
    AdapterProvenance(&'static str),
    #[error("the prompt or reference set differs from the reviewed set")]
    ReviewDrift,
    #[error("the adapter's output hash is not the stored bytes' hash")]
    OutputHash,
    #[error("the asset's bytes are not stored")]
    MissingBytes,
    #[error("the stored bytes do not hash to the recorded content hash")]
    HashMismatch,
    #[error("the payload is not a supported image of its declared type")]
    UnsupportedPayload,
    /// The payload passed a byte or pixel ceiling its caller set, named
    /// with its dimension (FIX 10654): never an unsupported graphic.
    #[error("graphic ceiling: {0}")]
    Capacity(CapacityHit),
    #[error("the destination is empty")]
    EmptyBounds,
    #[error("SVG refused at node {at} <{element}>: {refused:?}")]
    Svg {
        at: usize,
        element: String,
        refused: Refused,
    },
    /// The compile's memory was refused at the machine's floor, or its wait
    /// or deadline ran out: never an unsupported graphic.
    #[error(transparent)]
    Resource(#[from] ResourceRefusal),
}

impl GraphicError {
    /// The refusal, when memory or a deadline stopped the compile.
    #[must_use]
    pub const fn resource(&self) -> Option<ResourceRefusal> {
        match self {
            Self::Resource(refusal) => Some(*refusal),
            _ => None,
        }
    }

    /// The ceiling, when the payload passed one.
    #[must_use]
    pub const fn capacity(&self) -> Option<CapacityHit> {
        match self {
            Self::Capacity(hit) => Some(*hit),
            _ => None,
        }
    }
}

/// Why an SVG left the closed subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Scripts, event attributes, animation.
    Active,
    /// A reference to anything outside the document.
    ExternalReference,
    ForeignObject,
    /// Style sheets, `style` and `class`.
    Css,
    Filter,
    Mask,
    Pattern,
    ClipPath,
    Gradient,
    TextOnPath,
    /// Text arrives as typed textboxes, never as SVG text.
    Text,
    /// A fill the nonzero and even-odd rules could paint differently.
    FillRule,
    /// A non-uniform scale on a stroked shape.
    StrokeTransform,
    /// A transform outside translate, scale and rotate, or a mix that skews
    /// or flips.
    Transform,
    /// An element outside the subset.
    Element,
    /// An attribute outside the subset.
    Attribute(String),
    /// A value the subset does not take, by attribute name.
    Value(String),
    /// A path command outside M L H V C Q Z.
    PathCommand(char),
    /// No viewBox, no explicit size, or a size that is not the viewBox's.
    Document,
    /// Geometry, with its stroke, outside the viewBox.
    Bounds,
    Limit,
    Malformed(&'static str),
    /// Memory or a deadline stopped the compile here; it reaches the caller
    /// as [`GraphicError::Resource`], not as a refused subset.
    Resource(ResourceRefusal),
}

/// Compile one placed asset: native shapes for an SVG, a verified binding for
/// a raster image. Never a raster fallback. An SVG's tree, shapes and
/// fill-rule proofs reserve their memory through `resources`.
pub fn compile_graphic(
    input: &GraphicInput<'_>,
    resources: &Resources,
) -> Result<CompiledGraphic, GraphicError> {
    let bytes = asset::admit(input)?;
    let record = input.record;
    let (output, original, placed) = match record.media {
        MediaType::Svg => {
            let drawing = svg::compile(bytes, input.bounds, resources)?;
            let original = Extent {
                cx: drawing.child.cx,
                cy: drawing.child.cy,
            };
            let placed = drawing.placed;
            (Output::Shapes(drawing), original, placed)
        }
        MediaType::Png | MediaType::Jpeg => {
            let original = asset::raster_extent(record.media, bytes, &input.limits)?;
            let placed = fit(original, input.bounds);
            let binding = ImageBinding {
                handle: input.binding.handle.clone(),
                media: record.media,
                placed,
            };
            (Output::Image(binding), original, placed)
        }
    };
    let generated = match &record.origin {
        Origin::Generated { receipt, .. } => Some(GenerationReceipt::clone(receipt)),
        _ => None,
    };
    Ok(CompiledGraphic {
        output,
        record: AssetUse {
            artifact: record.artifact.clone(),
            version: record.version,
            content_hash: record.content_hash,
            provenance: record.provenance.clone(),
            rights: record.rights.clone(),
            generated,
            original,
            placed,
            description: record.description.clone(),
        },
    })
}

/// `original` scaled uniformly to touch two sides of `bounds`, centred.
fn fit(original: Extent, bounds: Rect) -> Rect {
    let (ow, oh) = (i128::from(original.cx), i128::from(original.cy));
    let (bw, bh) = (i128::from(bounds.cx), i128::from(bounds.cy));
    let (cx, cy) = if bw * oh <= bh * ow {
        (bounds.cx, ratio(oh * bw, ow))
    } else {
        (ratio(ow * bh, oh), bounds.cy)
    };
    Rect {
        x: bounds.x + (bounds.cx - cx) / 2,
        y: bounds.y + (bounds.cy - cy) / 2,
        cx,
        cy,
    }
}

/// `num / den` rounded half up, for positive operands that fit an i64.
fn ratio(num: i128, den: i128) -> i64 {
    i64::try_from((2 * num + den) / (2 * den)).unwrap_or(i64::MAX)
}
