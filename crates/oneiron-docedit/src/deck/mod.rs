//! Typed, read-only deck views over a retained OPC package (ARCH-0077, "The
//! typed deck model"). A view keeps no writable copy of the XML: every value
//! names the part, element and attribute it was read from, and its state is
//! absent, explicit, schema default or unresolved. Identity evidence, the
//! animation index and dependency fingerprints are reported, never repaired.
//! The template view reads masters and layouts the same way, for creation.
mod animation;
mod colour;
mod fingerprint;
mod graph;
mod resolve;
mod shapes;
mod template;

pub use animation::{AnimationIndex, AnimationTarget, Connection, TargetRole, TextRange};
pub use colour::{Colour, ColourSpec, ColourTransform, Rgba};
pub(crate) use shapes::{group_matrix, guid};
pub use template::{LayoutView, MasterView, Spacing, TemplateView, TextStyle};

use crate::ooxml::{DOCUMENT_RELATIONSHIPS, XmlError};
use crate::retained_opc::{self, Package};
use graph::{Graph, P, P14};
use std::collections::BTreeMap;

/// The slide `creationId` extension (`p:cSld/p:extLst`).
const SLIDE_CREATION_EXT: &str = "{BB962C8B-B14F-4D97-AF65-F5344CB8AC3E}";

/// Why a deck could not be read at all. A value that cannot be resolved is
/// not an error: it is a [`State::Unresolved`] value naming a canon refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeckError {
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
    #[error("invalid deck: {0}")]
    Invalid(&'static str),
}

/// The canon refusals (ARCH-0077, "The 23 named refusals") a read reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    AmbiguousPlaceholder,
    UnresolvedEffectiveStyle,
    UnsupportedColourTransform,
    UnresolvedColourContext,
    NonInvertibleGroupTransform,
    UnrepresentableTransform,
}

/// A retained XML element: its part and document-order element index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetainedNode {
    pub part: String,
    pub index: usize,
}

/// The exact retained location an effective value was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub node: RetainedNode,
    /// The element's qualified name as written (`a:xfrm`).
    pub element: String,
    pub attribute: Option<String>,
}

/// The four provenance states. Unresolved values carry no guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Absent,
    Explicit,
    SchemaDefault,
    Unresolved(Refusal),
}

/// One effective value. `inherited` is false only when the target element
/// itself holds the value: an edit writes own properties, never this value.
#[derive(Debug, Clone, PartialEq)]
pub struct Value<T> {
    pub value: Option<T>,
    pub state: State,
    pub source: Option<Source>,
    pub inherited: bool,
}

impl<T> Value<T> {
    fn absent() -> Self {
        Self {
            value: None,
            state: State::Absent,
            source: None,
            inherited: false,
        }
    }
    fn schema_default(value: T) -> Self {
        Self {
            value: Some(value),
            state: State::SchemaDefault,
            source: None,
            inherited: false,
        }
    }
    fn unresolved(why: Refusal, source: Option<Source>) -> Self {
        Self {
            value: None,
            state: State::Unresolved(why),
            source,
            inherited: false,
        }
    }
}

/// A read-only view of every slide in presentation order.
#[derive(Debug, Clone)]
pub struct DeckView {
    pub slides: Vec<SlideView>,
    /// Duplicate identity evidence, reported and never repaired.
    pub ambiguities: Vec<Ambiguity>,
}

#[derive(Debug, Clone)]
pub struct SlideView {
    pub part: String,
    /// `p:sldId/@id` in the presentation.
    pub sld_id: u32,
    /// `p14:creationId/@val`; inspection never mints one.
    pub creation_id: Option<u32>,
    pub layout: Option<String>,
    pub master: Option<String>,
    pub theme: Option<String>,
    /// Every shape in document order, nested group members included.
    pub shapes: Vec<ShapeView>,
    pub animation: AnimationIndex,
    /// Hash of the normalized slide element.
    pub content_fingerprint: [u8; 32],
    /// Hash of the slide and every rendering dependency.
    pub render_fingerprint: [u8; 32],
    /// The parts the render fingerprint covers, each with its byte hash.
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub part: String,
    /// BLAKE3 of the part bytes; all zero when the target part is missing.
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ambiguity {
    DuplicateSlideCreationId {
        creation_id: u32,
        slides: Vec<usize>,
    },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKind {
    Shape,
    Picture,
    GraphicFrame,
    Connector,
    Group,
}

#[derive(Debug, Clone)]
pub struct ShapeView {
    pub node: RetainedNode,
    pub kind: ShapeKind,
    /// `p:cNvPr/@id`, evidence within the slide.
    pub id: Option<u32>,
    /// `a16:creationId/@id`, as an uppercase braced GUID.
    pub creation_id: Option<String>,
    pub name: Option<String>,
    /// Indices into [`SlideView::shapes`] of enclosing groups, outermost
    /// first. A structural hint, not identity.
    pub group_path: Vec<usize>,
    pub placeholder: Option<Placeholder>,
    pub geometry: Geometry,
    pub text: Option<TextView>,
    pub content_fingerprint: [u8; 32],
}

/// `p:ph`, with the schema's implied `obj` type and index 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    pub kind: String,
    pub idx: u32,
}

/// The geometry resolver: own `a:xfrm`, then the matching layout and master
/// placeholders. An `a:xfrm` is inherited whole, never attribute by attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct Geometry {
    pub offset: Value<(i64, i64)>,
    pub extent: Value<(i64, i64)>,
    /// 60,000ths of a degree, clockwise.
    pub rotation: Value<i64>,
    pub flip_h: Value<bool>,
    pub flip_v: Value<bool>,
    /// Composed `p:grpSpPr/a:xfrm` matrices of every enclosing group, mapping
    /// this shape's coordinates to slide space.
    pub parent_transform: Value<Affine>,
}

impl Geometry {
    /// The verified slide-space top-left of the shape's frame, in EMU: its own
    /// rotation and flips about its centre, then every enclosing group, the
    /// least x and y of the four corners (ARCH-0077 shape anchor). `None` when
    /// any input is unresolved or the point leaves the coordinate range; never
    /// a guess.
    pub fn slide_space_top_left(&self) -> Option<(i64, i64)> {
        const RANGE: f64 = 27_273_042_316_900.0;
        if [
            self.offset.state,
            self.extent.state,
            self.rotation.state,
            self.flip_h.state,
            self.flip_v.state,
            self.parent_transform.state,
        ]
        .iter()
        .any(|state| matches!(state, State::Unresolved(_)))
        {
            return None;
        }
        let (off, ext) = (self.offset.value?, self.extent.value?);
        let matrix = self.parent_transform.value?;
        if ext.0 < 0 || ext.1 < 0 {
            return None;
        }
        let rot = self.rotation.value.unwrap_or(0) as f64;
        let sign = |flip: Option<bool>| if flip == Some(true) { -1.0 } else { 1.0 };
        let (fx, fy) = (sign(self.flip_h.value), sign(self.flip_v.value));
        let (sin, cos) = (rot / 60_000.0).to_radians().sin_cos();
        let (hx, hy) = (ext.0 as f64 / 2.0, ext.1 as f64 / 2.0);
        let centre = (off.0 as f64 + hx, off.1 as f64 + hy);
        let (x, y) = [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)]
            .into_iter()
            .map(|(u, v)| {
                let (x, y) = (u * hx * fx, v * hy * fy);
                matrix.apply(centre.0 + cos * x - sin * y, centre.1 + sin * x + cos * y)
            })
            .fold((f64::INFINITY, f64::INFINITY), |(mx, my), (x, y)| {
                (mx.min(x), my.min(y))
            });
        if !(x.is_finite() && y.is_finite()) || x.abs() > RANGE || y.abs() > RANGE {
            return None;
        }
        Some((x.round() as i64, y.round() as i64))
    }
}

/// `(x, y) -> (a·x + c·y + e, b·x + d·y + f)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Affine {
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
    pub e: f64,
    pub f: f64,
}

impl Affine {
    pub const IDENTITY: Self = Self {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        e: 0.0,
        f: 0.0,
    };
    pub fn apply(&self, x: f64, y: f64) -> (f64, f64) {
        (
            self.a * x + self.c * y + self.e,
            self.b * x + self.d * y + self.f,
        )
    }
    /// Compose: apply `inner`, then `outer`.
    pub fn then_outer(inner: Self, outer: Self) -> Self {
        Self {
            a: outer.a * inner.a + outer.c * inner.b,
            b: outer.b * inner.a + outer.d * inner.b,
            c: outer.a * inner.c + outer.c * inner.d,
            d: outer.b * inner.c + outer.d * inner.d,
            e: outer.a * inner.e + outer.c * inner.f + outer.e,
            f: outer.b * inner.e + outer.d * inner.f + outer.f,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TextView {
    pub body: BodyView,
    pub paragraphs: Vec<ParagraphView>,
}

/// The text-body resolver: `a:bodyPr` attributes one by one, and the autofit
/// element located separately.
#[derive(Debug, Clone, PartialEq)]
pub struct BodyView {
    pub node: Option<RetainedNode>,
    /// `lIns`, `tIns`, `rIns`, `bIns` in EMU.
    pub insets: [Value<i64>; 4],
    pub anchor: Value<String>,
    pub wrap: Value<String>,
    pub autofit: Value<Autofit>,
}

/// Existing autofit metrics are read as written; a view never recomputes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Autofit {
    None,
    Normal {
        font_scale: Option<u32>,
        line_reduction: Option<u32>,
    },
    Shape,
}

/// The paragraph resolver: own `a:pPr`, the shape's `a:lstStyle`, layout and
/// master placeholder styles, master `p:txStyles`, then `p:defaultTextStyle`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParagraphView {
    pub node: RetainedNode,
    pub level: Value<u8>,
    pub align: Value<String>,
    pub bullet: Value<Bullet>,
    pub runs: Vec<RunView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bullet {
    None,
    Char(String),
    AutoNumber(String),
}

/// The run resolver: `a:rPr`, the paragraph's `a:defRPr`, then the paragraph
/// chain's `a:defRPr`; theme font references resolve last. `a:endParaRPr` is
/// not a fallback for ordinary runs.
#[derive(Debug, Clone, PartialEq)]
pub struct RunView {
    pub node: RetainedNode,
    pub text: String,
    /// Hundredths of a point.
    pub size: Value<u32>,
    pub bold: Value<bool>,
    pub italic: Value<bool>,
    pub latin: Value<Font>,
    pub colour: Value<Colour>,
}

/// A typeface as written (`+mj-lt`) and the face it resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Font {
    pub typeface: String,
    pub resolved: String,
}

impl DeckView {
    /// Read every slide without mutating `package`. Malformed structure the
    /// view depends on is an error; unresolvable values are reported per value.
    pub fn read(package: &Package) -> Result<Self, DeckError> {
        let graph = Graph::load(package)?;
        let presentation = graph.part(&graph.presentation)?;
        let tree = &presentation.tree;
        tree.root(P, "presentation")?;
        let mut slides = Vec::new();
        if let Some(list) = graph::child(tree, 0, P, "sldIdLst") {
            for (_, entry) in tree.children(list) {
                if !entry.is(P, "sldId") {
                    continue;
                }
                let sld_id = entry
                    .attr("id")
                    .and_then(|id| id.parse::<u32>().ok())
                    .ok_or(DeckError::Invalid("slide id"))?;
                let rel = entry
                    .attr_ns(DOCUMENT_RELATIONSHIPS, "id")
                    .and_then(|id| presentation.rels.iter().find(|rel| rel.id == id))
                    .filter(|rel| rel.kind == "slide")
                    .and_then(|rel| rel.target.clone())
                    .ok_or(DeckError::Invalid("slide relationship"))?;
                slides.push(read_slide(package, &graph, rel, sld_id)?);
            }
        }
        let ambiguities = ambiguities(&slides);
        Ok(Self {
            slides,
            ambiguities,
        })
    }

    /// The dependency index: slides whose render fingerprint covers `part`.
    pub fn slides_depending_on(&self, part: &str) -> Vec<usize> {
        self.slides
            .iter()
            .enumerate()
            .filter(|(_, slide)| slide.dependencies.iter().any(|dep| dep.part == part))
            .map(|(index, _)| index)
            .collect()
    }
}

fn read_slide(
    package: &Package,
    graph: &Graph,
    part: String,
    sld_id: u32,
) -> Result<SlideView, DeckError> {
    let tree = &graph.part(&part)?.tree;
    tree.root(P, "sld")?;
    let layout = graph.related(&part, "slideLayout")?;
    let master = layout
        .map(|layout| graph.related(layout, "slideMaster"))
        .transpose()?
        .flatten();
    let theme = master
        .map(|master| graph.related(master, "theme"))
        .transpose()?
        .flatten();
    let context = resolve::SlideContext {
        graph,
        slide: &part,
        layout,
        master,
        theme,
    };
    let shapes = match graph::path(tree, 0, &[(P, "cSld"), (P, "spTree")]) {
        Some(sp_tree) => shapes::walk(&context, sp_tree),
        None => Vec::new(),
    };
    let animation = animation::index(&part, tree, &shapes);
    let (render_fingerprint, dependencies) = fingerprint::render(package, graph, &part)?;
    Ok(SlideView {
        sld_id,
        creation_id: slide_creation_id(tree)?,
        layout: layout.map(str::to_owned),
        master: master.map(str::to_owned),
        theme: theme.map(str::to_owned),
        shapes,
        animation,
        content_fingerprint: fingerprint::content(tree, 0),
        render_fingerprint,
        dependencies,
        part,
    })
}

fn slide_creation_id(tree: &crate::ooxml::XmlTree) -> Result<Option<u32>, DeckError> {
    let Some(list) = graph::path(tree, 0, &[(P, "cSld"), (P, "extLst")]) else {
        return Ok(None);
    };
    let mut found = None;
    for (index, ext) in tree.children(list) {
        if !ext.is(P, "ext") || ext.attr("uri") != Some(SLIDE_CREATION_EXT) {
            continue;
        }
        let value = graph::child(tree, index, P14, "creationId")
            .and_then(|id| tree.nodes[id].attr("val"))
            .and_then(|val| val.parse::<u32>().ok())
            .ok_or(DeckError::Invalid("slide creation id"))?;
        if found.replace(value).is_some() {
            return Err(DeckError::Invalid("duplicate slide creation id extension"));
        }
    }
    Ok(found)
}

fn ambiguities(slides: &[SlideView]) -> Vec<Ambiguity> {
    let mut found = Vec::new();
    let mut creation: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, slide) in slides.iter().enumerate() {
        if let Some(id) = slide.creation_id {
            creation.entry(id).or_default().push(index);
        }
    }
    for (creation_id, owners) in creation {
        if owners.len() > 1 {
            found.push(Ambiguity::DuplicateSlideCreationId {
                creation_id,
                slides: owners,
            });
        }
    }
    for (slide, view) in slides.iter().enumerate() {
        let mut ids: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        let mut guids: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, shape) in view.shapes.iter().enumerate() {
            if let Some(id) = shape.id {
                ids.entry(id).or_default().push(index);
            }
            if let Some(guid) = shape.creation_id.as_deref() {
                guids.entry(guid).or_default().push(index);
            }
        }
        for (id, shapes) in ids {
            if shapes.len() > 1 {
                found.push(Ambiguity::DuplicateShapeId { slide, id, shapes });
            }
        }
        for (id, shapes) in guids {
            if shapes.len() > 1 {
                found.push(Ambiguity::DuplicateShapeCreationId {
                    slide,
                    id: id.to_owned(),
                    shapes,
                });
            }
        }
    }
    found
}

/// Read a DrawingML boolean (`1`/`true`, `0`/`false`).
fn boolean(value: &str) -> Option<bool> {
    match value {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod tests;
