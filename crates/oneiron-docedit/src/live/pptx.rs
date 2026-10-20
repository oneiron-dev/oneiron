//! The live deck model: tree, text bodies, stamped operations, attribution,
//! three-way forks and landing (ARCH-0077 section "Multiplayer").
//!
//! Model identity ([`NodeId`]) is minted here and never reused; the native
//! `p:cNvPr/@id` within its slide part is retained as format evidence on the
//! node's [`NodeBinding`], exactly as the anchor contract keeps them apart.
//! Sibling position in `children` is the only order. Imported content has
//! unknown authorship: no importer or OOXML author name is ever recorded as
//! its maker.

use super::LiveError;
use super::conversion::Conversion;
use super::convert::{self, HELD_MEDIA};
use super::points::GeomPath;
use super::{diagram, held, points};
use crate::deck::{DeckView, ShapeKind, ShapeView, TextView};
use crate::edit::{AssetRef, BREAK, ConnectorPreset, Digest, Effect, IdMarks, Preset};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod chart;
mod merge;
mod table;
mod table_ops;

pub use chart::{ChartKind, ChartSeries, ChartSource};
pub use merge::{diff, preflight, preflight_merged};
pub use table::{MergeFault, TableBinding, TableBody, TableEdit, TableMerge};
pub(crate) use table::{UNBOUND_GRID, positions};

/// Model identity for slides, shapes, paragraphs, and a table's rows and
/// columns. The root is `NodeId(0)`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
pub struct NodeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Root,
    Slide,
    Group,
    Shape,
    Picture,
    GraphicFrame,
    Connector,
}

impl NodeKind {
    /// Whether a node of this kind may hold a child of `kind`: slides belong
    /// under the root; groups and shapes under slides or groups. A group
    /// cannot contain slides.
    pub fn holds(self, kind: NodeKind) -> bool {
        match kind {
            NodeKind::Slide => self == NodeKind::Root,
            NodeKind::Root => false,
            _ => matches!(self, NodeKind::Slide | NodeKind::Group),
        }
    }
}

/// How a live node binds to retained package evidence. Absent for nodes born
/// in the live body that no import produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeBinding {
    /// The slide part this node was read from.
    pub slide_part: String,
    /// `p:cNvPr/@id` (shapes) or `p:sldId/@id` (slides) as imported.
    pub native_id: Option<u32>,
    /// `a16:creationId` (shapes) or `p14:creationId` (slides, decimal).
    pub creation_id: Option<String>,
    /// Content fingerprint at import; the staleness guard for export edits.
    pub fingerprint: [u8; 32],
    /// A table frame's rows and columns as its retained XML holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<TableBinding>,
}

/// Own (never inherited) geometry, in EMU and 60,000ths of a degree.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct GeometryProps {
    pub offset: Option<(i64, i64)>,
    pub extent: Option<(i64, i64)>,
    pub rotation: Option<i64>,
    pub flip_h: Option<bool>,
    pub flip_v: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckNode {
    pub kind: NodeKind,
    pub parent: Option<NodeId>,
    /// Sibling order is position in this list; there is no other order.
    pub children: Vec<NodeId>,
    pub name: Option<String>,
    pub binding: Option<NodeBinding>,
    pub geometry: GeometryProps,
    /// Placeholder kind/index as read (`p:ph`), for export evidence.
    pub placeholder: Option<(String, u32)>,
    /// A shape's preset geometry, or the shape a picture is cropped to
    /// (PowerPoint's Crop to Shape: the picture keeps its media and crop). A
    /// live-born shape's or picture's `None` is a rectangle; an imported
    /// one's is a preset outside the written set, kept as written, or custom
    /// geometry, which a shape's payload marks.
    #[serde(default)]
    pub preset: Option<Preset>,
    /// What a shape, picture, graphic frame or connector is written from.
    /// Import reads a shape's custom geometry paths, a picture's media, a
    /// table's cells, a chart's data, a SmartArt's nodes, an OLE object's
    /// program id and preview, and a connector's geometry and glue; any
    /// other frame stays in the retained markup (`None`).
    #[serde(default)]
    pub payload: Option<NodePayload>,
}

/// What a node is written from. A live-born node carries a picture (an
/// engine asset or an image the deck holds), table, chart, SmartArt,
/// freeform or connector; the held forms (an imported picture's media, a
/// SmartArt, an OLE object, custom geometry) are read from the retained
/// package. A picture may show any image the deck holds, a SmartArt takes
/// nodes added, removed, moved or re-worded, and a shape takes new points;
/// an OLE object is read only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodePayload {
    /// A raster asset by its engine identity; the export's resolver supplies
    /// the admitted record and bytes, which must hash to the reference.
    Picture { image: AssetRef },
    /// An imported picture's media as the retained package holds it. A
    /// picture takes new media as an engine asset ([`Self::Picture`]), and
    /// shows any image part the deck holds again under this payload.
    HeldPicture { media: HeldMedia },
    /// A native table: rows and columns by stable identity, cells by row and
    /// column, and merge rectangles by corner identity ([`TableBody`]).
    Table(TableBody),
    /// A classic chart: one category per point, each series one value per
    /// category (`None` is a missing point), or a scatter series one value
    /// per x value.
    Chart {
        family: ChartKind,
        categories: Vec<String>,
        series: Vec<ChartSeries>,
        /// Where the data lives; a live-born chart's is its own workbook.
        #[serde(default)]
        source: ChartSource,
    },
    /// A connector, each end glued to a node on its slide or free. `None`
    /// is a preset outside the written set (or custom geometry), kept as
    /// written; a live-born connector's is straight.
    Connector {
        #[serde(default)]
        preset: Option<ConnectorPreset>,
        #[serde(default)]
        start: Option<ConnectorEnd>,
        #[serde(default)]
        end: Option<ConnectorEnd>,
    },
    /// A SmartArt graphic's nodes, read from its data part, in outline
    /// order. Nodes are written as PowerPoint's text pane writes them: text
    /// in place, or nodes added, removed and moved with the diagram laid
    /// out again by PowerPoint; a live-born one is the engine's outline list.
    SmartArt { nodes: Vec<SmartArtNode> },
    /// An embedded or linked OLE object: its program id and the preview
    /// picture its fallback shows.
    Ole {
        prog_id: Option<String>,
        preview: Option<HeldMedia>,
    },
    /// A shape drawn from custom geometry (`a:custGeom`): its paths, as
    /// Edit Points draws them. New paths redraw the outline, and a preset
    /// shape given paths becomes a freeform; a preset replaces the paths, as
    /// PowerPoint's Change Shape does on a freeform, and the export names
    /// the replacement.
    CustomGeometry { paths: Vec<GeomPath> },
}

/// Media the retained package holds, by its part and the BLAKE3 hash of its
/// bytes: the identity of media that has no engine asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HeldMedia {
    pub part: String,
    pub hash: Digest,
}

/// One SmartArt node's text (paragraphs joined by `\n`), its depth below
/// the diagram's root, and its identity: the data part's model id. A node
/// written with no id, or one the SmartArt does not hold, is new; when no
/// node names one, nodes keep the held ones by place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SmartArtNode {
    pub text: String,
    pub level: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// One glued connector end: the node and its geometry's connection site
/// index. Glue to a node that is not on the connector's slide at export is
/// dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorEnd {
    pub node: NodeId,
    pub site: u32,
}

impl NodePayload {
    /// The node kind this payload belongs to.
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Picture { .. } | Self::HeldPicture { .. } => NodeKind::Picture,
            Self::Table { .. } | Self::Chart { .. } | Self::SmartArt { .. } | Self::Ole { .. } => {
                NodeKind::GraphicFrame
            }
            Self::Connector { .. } => NodeKind::Connector,
            Self::CustomGeometry { .. } => NodeKind::Shape,
        }
    }

    /// Whether this payload is a held form, read from the retained package.
    pub fn held(&self) -> bool {
        matches!(
            self,
            Self::HeldPicture { .. }
                | Self::SmartArt { .. }
                | Self::Ole { .. }
                | Self::CustomGeometry { .. }
        )
    }

    /// A chart's series fit its categories: a category series holds no
    /// more values than there are categories (a shorter one ends in missing
    /// points; no categories is points by index), and only a scatter series
    /// carries x values, at least one per value.
    pub fn check(&self) -> Result<(), LiveError> {
        let Self::Chart {
            family,
            categories,
            series,
            ..
        } = self
        else {
            return Ok(());
        };
        for line in series {
            if line.family.unwrap_or(*family) == ChartKind::Scatter {
                if line.x.as_ref().is_some_and(|x| x.len() < line.values.len()) {
                    return Err(LiveError::Invalid(
                        "a scatter series holds more values than x values",
                    ));
                }
            } else if line.x.is_some() {
                return Err(LiveError::Invalid("only a scatter series has x values"));
            } else if !categories.is_empty() && line.values.len() > categories.len() {
                return Err(LiveError::Invalid(
                    "a chart series holds more values than there are categories",
                ));
            }
        }
        Ok(())
    }

    /// The payload a node takes when this one is written to it, and what
    /// the write did PowerPoint's way where the deck once refused it (the
    /// Office ruling of 10-18: never refuse an edit PowerPoint performs).
    /// `held` is the node's current payload, `bound` whether the node is
    /// read from the retained package, and `parts` the hashes of the
    /// package's other parts.
    ///
    /// A picture, imported or live-born, shows any image part the deck
    /// holds; a SmartArt settles its nodes' levels and identities
    /// ([`diagram::settle`]); a shape takes paths naming only guides it
    /// defines; a table settles to its one written form. A chart settles as
    /// [`convert::settle_chart`] lays it out: Change Chart Type between any
    /// families, for the chart or one series, data written to a chart read
    /// from its caches embedded, and a live-born chart of any family over
    /// its own workbook.
    fn settle(
        &self,
        held: Option<&NodePayload>,
        bound: bool,
        parts: &BTreeMap<String, [u8; 32]>,
    ) -> Result<(NodePayload, Vec<Conversion>), LiveError> {
        let same = || -> Result<(NodePayload, Vec<Conversion>), LiveError> {
            Ok((self.clone(), Vec::new()))
        };
        match self {
            Self::Picture { .. } | Self::Connector { .. } => same(),
            Self::HeldPicture { media } => {
                if held == Some(self)
                    || (convert::image_part(&media.part)
                        && parts.get(&media.part) == Some(&media.hash.0))
                {
                    same()
                } else {
                    Err(LiveError::Invalid(HELD_MEDIA))
                }
            }
            Self::SmartArt { nodes } => {
                let was = match (held, bound) {
                    (Some(Self::SmartArt { nodes: was }), true) => was.as_slice(),
                    // Kept: PowerPoint has no direct swap of a table or
                    // chart for a diagram.
                    (_, true) => return Err(LiveError::Invalid(WRITTEN_FRAME)),
                    (_, false) => &[],
                };
                let (nodes, done) = diagram::settle(was, nodes);
                Ok((Self::SmartArt { nodes }, done))
            }
            // Kept: an OLE object's program id and preview are its embedded
            // object's own, made by its server application: changing them
            // needs the embedding app, which the deck does not run.
            Self::Ole { .. } => {
                if bound && held == Some(self) {
                    same()
                } else {
                    Err(LiveError::Invalid(HELD))
                }
            }
            Self::CustomGeometry { paths } => {
                let was = match held {
                    Some(Self::CustomGeometry { paths: was }) => was.as_slice(),
                    _ => &[],
                };
                points::check(paths, was)?;
                same()
            }
            Self::Table(table) => {
                // A table is a grid of its rows and columns: a cell it does
                // not hold is empty ([`TableBody::settle`]).
                let was = match held {
                    Some(Self::Table(was)) => Some(was),
                    _ => None,
                };
                let (table, done) = table.settled(was)?;
                // Kept: PowerPoint has no direct table/chart swap: it turns
                // no chart or diagram into a table.
                if bound && was.is_none() {
                    return Err(LiveError::Invalid(WRITTEN_FRAME));
                }
                Ok((Self::Table(table), done))
            }
            Self::Chart { .. } => {
                // Kept: PowerPoint has no direct table/chart swap, and a
                // chart the reader cannot read has no live form to write
                // over.
                if bound && !matches!(held, Some(Self::Chart { .. })) {
                    return Err(LiveError::Invalid(WRITTEN_FRAME));
                }
                convert::settle_chart(held.filter(|_| bound), self)
            }
        }
    }

    /// The asset a picture payload names.
    pub fn picture(&self) -> Option<&AssetRef> {
        match self {
            Self::Picture { image } => Some(image),
            _ => None,
        }
    }
}

/// The held-form refusal: an OLE object's program and preview are read
/// from the retained package; changing them needs the embedding app.
pub(crate) const HELD: &str =
    "read from the retained package: no deck op writes an OLE object (it needs its embedding app)";
/// The empty-table refusal: a table holds at least one row and column.
pub(crate) const WRITTEN_TABLE: &str =
    "a table holds at least one row and one column; RemoveNode removes the table";
/// A written frame stays the kind of frame the live deck read in it.
pub(crate) const WRITTEN_FRAME: &str =
    "a written frame keeps the table or chart the live deck reads in it";

/// One run of a paragraph. Formatting rides as run-property marks; scheme
/// colour and hyperlinks stay atomic values on the run that carries them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Run {
    pub text: String,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    /// Hundredths of a point.
    pub size: Option<u32>,
    pub latin: Option<String>,
}

/// A paragraph with a stable identity, kept across text edits to its runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Paragraph {
    pub id: NodeId,
    pub level: u8,
    pub runs: Vec<Run>,
}

impl Paragraph {
    pub fn text(&self) -> String {
        self.runs.iter().map(|run| run.text.as_str()).collect()
    }
}

/// One rich-text body per text shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextBody {
    pub paragraphs: Vec<Paragraph>,
}

impl TextBody {
    /// The plain mapping the edit verbs use: `\n` between paragraphs.
    pub fn plain(&self) -> String {
        self.paragraphs
            .iter()
            .map(Paragraph::text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The whole live deck: one tree, text bodies keyed by their shape node, and
/// the content hashes of every opaque (non-slide) retained part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveDeck {
    pub nodes: BTreeMap<NodeId, DeckNode>,
    pub texts: BTreeMap<NodeId, TextBody>,
    /// BLAKE3 of each opaque part's bytes (masters, layouts, themes, media).
    pub opaque_parts: BTreeMap<String, [u8; 32]>,
    /// Next model identity to mint. Never decreases, never reuses.
    pub next_node: u64,
    /// Count of operations applied since import; the preflight pins it.
    pub version: u64,
    /// Native-id allocation history: every slide and shape id the retained
    /// packages this deck was bound to have held. An export allocates new
    /// native ids above it, so a removed node's id is never reused.
    pub id_marks: IdMarks,
}

impl LiveDeck {
    /// Import a retained package into the live model. Authorship of every
    /// imported node is unknown by construction.
    pub fn import(package: &Package) -> Result<Self, LiveError> {
        let view = DeckView::read(package)?;
        let mut deck = Self {
            nodes: BTreeMap::new(),
            texts: BTreeMap::new(),
            opaque_parts: BTreeMap::new(),
            next_node: 1,
            version: 0,
            id_marks: IdMarks::of_deck(&view),
        };
        deck.nodes.insert(
            NodeId(0),
            DeckNode {
                kind: NodeKind::Root,
                parent: None,
                children: Vec::new(),
                name: None,
                binding: None,
                geometry: GeometryProps::default(),
                placeholder: None,
                preset: None,
                payload: None,
            },
        );
        let slide_parts: BTreeSet<&str> = view
            .slides
            .iter()
            .map(|slide| slide.part.as_str())
            .collect();
        for slide in &view.slides {
            let slide_id = deck.mint();
            deck.nodes.insert(
                slide_id,
                DeckNode {
                    kind: NodeKind::Slide,
                    parent: Some(NodeId(0)),
                    children: Vec::new(),
                    name: None,
                    binding: Some(NodeBinding {
                        slide_part: slide.part.clone(),
                        native_id: Some(slide.sld_id),
                        creation_id: slide.creation_id.map(|id| id.to_string()),
                        fingerprint: slide.content_fingerprint,
                        table: None,
                    }),
                    geometry: GeometryProps::default(),
                    placeholder: None,
                    preset: None,
                    payload: None,
                },
            );
            deck.nodes
                .get_mut(&NodeId(0))
                .expect("root inserted above")
                .children
                .push(slide_id);
            // First pass mints every shape identity in document order; the
            // second wires parents from each shape's group path.
            let mut ids: Vec<NodeId> = Vec::with_capacity(slide.shapes.len());
            let tree = held::slide_tree(package, &slide.part)?;
            for shape in &slide.shapes {
                let id = deck.mint();
                ids.push(id);
                let geometry = geometry_of(shape);
                deck.nodes.insert(
                    id,
                    DeckNode {
                        kind: match shape.kind {
                            ShapeKind::Shape => NodeKind::Shape,
                            ShapeKind::Picture => NodeKind::Picture,
                            ShapeKind::GraphicFrame => NodeKind::GraphicFrame,
                            ShapeKind::Connector => NodeKind::Connector,
                            ShapeKind::Group => NodeKind::Group,
                        },
                        parent: Some(slide_id),
                        children: Vec::new(),
                        name: shape.name.clone(),
                        binding: Some(NodeBinding {
                            slide_part: slide.part.clone(),
                            native_id: shape.id,
                            creation_id: shape.creation_id.clone(),
                            fingerprint: shape.content_fingerprint,
                            table: None,
                        }),
                        geometry,
                        placeholder: shape
                            .placeholder
                            .as_ref()
                            .map(|ph| (ph.kind.clone(), ph.idx)),
                        preset: None,
                        payload: None,
                    },
                );
                if let Some(text) = &shape.text {
                    let body = text_body(text, &tree, || deck.mint());
                    deck.texts.insert(id, body);
                }
            }
            for (index, shape) in slide.shapes.iter().enumerate() {
                let parent = shape
                    .group_path
                    .last()
                    .map_or(slide_id, |group| ids[*group]);
                let id = ids[index];
                deck.nodes
                    .get_mut(&id)
                    .expect("shape inserted above")
                    .parent = Some(parent);
                deck.nodes
                    .get_mut(&parent)
                    .expect("parent inserted above")
                    .children
                    .push(id);
            }
            // Third, what each element is written as, glue by live node.
            let native: BTreeMap<u32, NodeId> = slide
                .shapes
                .iter()
                .zip(&ids)
                .filter_map(|(shape, id)| Some((shape.id?, *id)))
                .collect();
            // A table's rows and columns are minted once, here, in retained
            // order, and bound to the coordinates its XML holds them at.
            for (shape, id) in slide.shapes.iter().zip(&ids) {
                let (payload, table) = match held::table::import(&tree, shape, || deck.mint()) {
                    Some((body, binding)) => (Some(NodePayload::Table(body)), Some(binding)),
                    None => (
                        held::payload(package, &slide.part, &tree, shape, |at| {
                            native.get(&at).copied()
                        }),
                        None,
                    ),
                };
                let node = deck.nodes.get_mut(id).expect("shape inserted above");
                node.preset = held::shape_preset(&tree, shape);
                node.payload = payload;
                if let Some(binding) = &mut node.binding {
                    binding.table = table;
                }
            }
        }
        for name in package.names() {
            if slide_parts.contains(name) {
                continue;
            }
            if let Some(bytes) = package.part(name)? {
                deck.opaque_parts
                    .insert(name.to_owned(), *blake3::hash(&bytes).as_bytes());
            }
        }
        Ok(deck)
    }

    fn mint(&mut self) -> NodeId {
        while self.nodes.contains_key(&NodeId(self.next_node)) {
            self.next_node += 1;
        }
        let id = NodeId(self.next_node);
        self.next_node += 1;
        id
    }

    /// The identity a creation names, or a fresh mint. A named identity
    /// already in the tree refuses: identities are never reused.
    fn take(&mut self, id: Option<NodeId>) -> Result<NodeId, LiveError> {
        match id {
            None => Ok(self.mint()),
            Some(id) if id == NodeId(0) || self.nodes.contains_key(&id) => {
                Err(LiveError::Invalid("the node identity is taken"))
            }
            Some(id) => Ok(id),
        }
    }

    /// Canonical state hash at the current version (export memo-key input).
    pub fn state_hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Semantic equality ignoring the operation counter: the fixed-point
    /// comparison of step 3 of the eight-step check.
    pub fn semantically_eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
            && self.texts == other.texts
            && self.opaque_parts == other.opaque_parts
    }

    /// Every descendant of `node`, in tree order.
    pub fn descendants(&self, node: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack: Vec<NodeId> = self
            .nodes
            .get(&node)
            .map(|found| found.children.clone())
            .unwrap_or_default();
        stack.reverse();
        while let Some(id) = stack.pop() {
            out.push(id);
            if let Some(found) = self.nodes.get(&id) {
                let mut children = found.children.clone();
                children.reverse();
                stack.extend(children);
            }
        }
        out
    }

    /// The slide part `node` lives on, through its binding or its slide
    /// ancestor's.
    pub fn slide_part_of(&self, mut node: NodeId) -> Option<String> {
        loop {
            let found = self.nodes.get(&node)?;
            if let Some(binding) = &found.binding {
                return Some(binding.slide_part.clone());
            }
            node = found.parent?;
        }
    }
}

/// A retained shape's own geometry, as the live model holds it.
pub(crate) fn geometry_of(shape: &ShapeView) -> GeometryProps {
    GeometryProps {
        offset: own(&shape.geometry.offset),
        extent: own(&shape.geometry.extent),
        rotation: own(&shape.geometry.rotation),
        flip_h: own(&shape.geometry.flip_h),
        flip_v: own(&shape.geometry.flip_v),
    }
}

/// A retained text body as the live model holds it, paragraph identities
/// drawn from `mint`. `tree` is the slide the body is read from: each soft
/// break (`a:br`) in it is a run of its own holding one U+000B, as the text
/// mapping counts it. A break declares no property, so its `a:rPr` stays
/// as written.
pub(crate) fn text_body(
    text: &TextView,
    tree: &XmlTree,
    mut mint: impl FnMut() -> NodeId,
) -> TextBody {
    TextBody {
        paragraphs: text
            .paragraphs
            .iter()
            .map(|paragraph| {
                let id = mint();
                let mut breaks = crate::deck::soft_breaks(tree, paragraph.node.index)
                    .into_iter()
                    .peekable();
                let mut runs = Vec::with_capacity(paragraph.runs.len());
                for (at, run) in paragraph.runs.iter().enumerate() {
                    while breaks.next_if_eq(&at).is_some() {
                        runs.push(soft_break());
                    }
                    runs.push(Run {
                        text: run.text.clone(),
                        bold: run.bold.value,
                        italic: run.italic.value,
                        size: run.size.value,
                        latin: run.latin.value.as_ref().map(|font| font.typeface.clone()),
                    });
                }
                runs.extend(breaks.map(|_| soft_break()));
                Paragraph {
                    id,
                    level: paragraph.level.value.unwrap_or(0),
                    runs,
                }
            })
            .collect(),
    }
}

/// A soft break in live text: one U+000B, declaring no property.
fn soft_break() -> Run {
    Run {
        text: BREAK.to_string(),
        bold: None,
        italic: None,
        size: None,
        latin: None,
    }
}

/// An effective value the target element itself holds; inherited values are
/// never materialised into the live model.
fn own<T: Clone>(value: &crate::deck::Value<T>) -> Option<T> {
    if value.inherited {
        None
    } else {
        value.value.clone()
    }
}

/// One deck operation. A move keeps the node's identity; a cross-slide move
/// is reported because it also changes relationship context. A creation
/// names the identity it makes, so replaying it onto another head (a fork's
/// merge, a concurrent peer) makes the same node; `None` mints one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckOp {
    AddSlide {
        #[serde(default)]
        id: Option<NodeId>,
    },
    /// A live-born node; a shape may name its preset, and a picture the
    /// shape it is cropped to; a picture, graphic frame or connector carries
    /// the payload it is written from.
    AddNode {
        #[serde(default)]
        id: Option<NodeId>,
        parent: NodeId,
        kind: NodeKind,
        name: Option<String>,
        index: Option<usize>,
        #[serde(default)]
        preset: Option<Preset>,
        #[serde(default)]
        payload: Option<NodePayload>,
    },
    RemoveNode {
        node: NodeId,
    },
    MoveNode {
        node: NodeId,
        new_parent: NodeId,
        index: usize,
    },
    /// Replace a text shape's whole body; paragraph identities are caller
    /// supplied so unchanged paragraphs keep theirs.
    SetText {
        node: NodeId,
        body: TextBody,
    },
    /// Formatting-only change to the runs of one paragraph.
    SetRunMarks {
        node: NodeId,
        paragraph: NodeId,
        runs: Vec<Run>,
    },
    SetGeometry {
        node: NodeId,
        geometry: GeometryProps,
    },
    /// A shape's preset geometry, as Change Shape writes it, replacing a
    /// freeform's paths; or a picture's, as Crop to Shape writes it, the
    /// picture keeping its media and crop.
    SetPreset {
        node: NodeId,
        preset: Preset,
    },
    /// What a shape, picture, graphic frame or connector is written from:
    /// a shape's points, new media or held media the deck holds, a table's
    /// cells, a chart's data, a SmartArt's nodes, or a connector's geometry
    /// and glue. A written table or chart may change shape (rows, columns,
    /// series, categories), and a chart its type, for the whole chart or one
    /// series, as PowerPoint does; the export rewrites it. A reshaped
    /// written table's frame takes its grid's size: its own extent clears.
    /// A whole table written over a table is logged as the table edits that
    /// make it ([`LiveDeck::lower`]). The edit's effects name what it did
    /// PowerPoint's way.
    SetPayload {
        node: NodeId,
        payload: NodePayload,
    },
    /// Edits to the table a graphic frame holds, by row and column
    /// identity, in order. A reshaped written table's frame takes its grid's
    /// size: its own extent clears.
    EditTable {
        node: NodeId,
        edits: Vec<TableEdit>,
    },
    /// Whole-part replacement of an opaque part, guarded by its source hash.
    ReplaceOpaque {
        part: String,
        expected: [u8; 32],
        replacement: [u8; 32],
    },
}

impl DeckOp {
    /// The node this operation touches, when it touches exactly one.
    pub fn target(&self) -> Option<NodeId> {
        match self {
            DeckOp::AddNode { parent, .. } => Some(*parent),
            DeckOp::RemoveNode { node }
            | DeckOp::MoveNode { node, .. }
            | DeckOp::SetText { node, .. }
            | DeckOp::SetRunMarks { node, .. }
            | DeckOp::SetGeometry { node, .. }
            | DeckOp::SetPreset { node, .. }
            | DeckOp::SetPayload { node, .. }
            | DeckOp::EditTable { node, .. } => Some(*node),
            DeckOp::AddSlide { .. } | DeckOp::ReplaceOpaque { .. } => None,
        }
    }

    /// The asset a picture this operation writes names.
    pub fn picture(&self) -> Option<&AssetRef> {
        match self {
            DeckOp::AddNode {
                payload: Some(payload),
                ..
            }
            | DeckOp::SetPayload { payload, .. } => payload.picture(),
            _ => None,
        }
    }

    /// The identity a creation names.
    pub fn created(&self) -> Option<NodeId> {
        match self {
            DeckOp::AddSlide { id } | DeckOp::AddNode { id, .. } => *id,
            _ => None,
        }
    }

    pub fn kind(&self) -> ChangeKind {
        match self {
            DeckOp::AddSlide { .. } | DeckOp::AddNode { .. } | DeckOp::RemoveNode { .. } => {
                ChangeKind::Creation
            }
            DeckOp::MoveNode { .. } => ChangeKind::Movement,
            DeckOp::SetText { .. } => ChangeKind::Text,
            DeckOp::SetRunMarks { .. } => ChangeKind::Formatting,
            DeckOp::SetGeometry { .. }
            | DeckOp::SetPreset { .. }
            | DeckOp::SetPayload { .. }
            | DeckOp::EditTable { .. }
            | DeckOp::ReplaceOpaque { .. } => ChangeKind::Property,
        }
    }
}

/// What an operation did to a unit, for attribution and effect descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Creation,
    Text,
    Formatting,
    Movement,
    Property,
    /// A container summarising edits below it; never written per keystroke
    /// onto the slide itself.
    Descendant,
}

/// Every operation says who made it. `made_by` is the actor the engine bound
/// to the writing peer; it is attribution evidence, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StampedOp {
    pub made_by: String,
    pub at: u64,
    pub op: DeckOp,
}

impl LiveDeck {
    /// Apply one stamped operation, validating the tree rules. Returns the
    /// nodes the operation affected (the target plus, for a removal, its
    /// former subtree).
    pub fn apply(&mut self, stamped: &StampedOp) -> Result<Vec<NodeId>, LiveError> {
        self.apply_with_effects(stamped)
            .map(|(affected, _)| affected)
    }

    /// [`Self::apply`], with what the operation did PowerPoint's way where
    /// the deck once refused it (the Office ruling of 10-18), each an
    /// [`Effect::Converted`] on the node it names, for the edit's receipt.
    pub fn apply_with_effects(
        &mut self,
        stamped: &StampedOp,
    ) -> Result<(Vec<NodeId>, Vec<Effect>), LiveError> {
        let mut effects = Vec::new();
        let affected = match &stamped.op {
            DeckOp::AddSlide { id } => {
                let id = self.take(*id)?;
                self.nodes.insert(
                    id,
                    DeckNode {
                        kind: NodeKind::Slide,
                        parent: Some(NodeId(0)),
                        children: Vec::new(),
                        name: None,
                        binding: None,
                        geometry: GeometryProps::default(),
                        placeholder: None,
                        preset: None,
                        payload: None,
                    },
                );
                self.nodes
                    .get_mut(&NodeId(0))
                    .ok_or(LiveError::UnknownNode)?
                    .children
                    .push(id);
                vec![id]
            }
            DeckOp::AddNode {
                id,
                parent,
                kind,
                name,
                index,
                preset,
                payload,
            } => {
                self.check_parent(*parent, *kind)?;
                if preset.is_some() && !takes_preset(*kind) {
                    return Err(LiveError::Invalid(ONLY_SHAPE_OR_PICTURE));
                }
                if payload
                    .as_ref()
                    .is_some_and(|payload| payload.kind() != *kind)
                {
                    return Err(LiveError::Invalid(
                        "the payload does not belong to the node kind",
                    ));
                }
                let (payload, done) = match payload {
                    Some(payload) => {
                        let (settled, done) = payload.settle(None, false, &self.opaque_parts)?;
                        settled.check()?;
                        (Some(settled), done)
                    }
                    None => (None, Vec::new()),
                };
                // A live-born freeform's paths are its outline: no preset.
                let preset = if matches!(payload, Some(NodePayload::CustomGeometry { .. })) {
                    None
                } else {
                    *preset
                };
                let id = self.take(*id)?;
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: id,
                    conversion,
                }));
                self.nodes.insert(
                    id,
                    DeckNode {
                        kind: *kind,
                        parent: Some(*parent),
                        children: Vec::new(),
                        name: name.clone(),
                        binding: None,
                        geometry: GeometryProps::default(),
                        placeholder: None,
                        preset,
                        payload,
                    },
                );
                let children = &mut self
                    .nodes
                    .get_mut(parent)
                    .ok_or(LiveError::UnknownNode)?
                    .children;
                let at = index.map_or(children.len(), |i| i.min(children.len()));
                children.insert(at, id);
                vec![id, *parent]
            }
            DeckOp::RemoveNode { node } => {
                if *node == NodeId(0) {
                    return Err(LiveError::TreeShape("the root is not removable"));
                }
                let mut gone = self.descendants(*node);
                gone.push(*node);
                let parent = self.nodes.get(node).ok_or(LiveError::UnknownNode)?.parent;
                if let Some(parent) = parent
                    && let Some(found) = self.nodes.get_mut(&parent)
                {
                    found.children.retain(|child| child != node);
                }
                for id in &gone {
                    self.nodes.remove(id);
                    self.texts.remove(id);
                }
                gone
            }
            DeckOp::MoveNode {
                node,
                new_parent,
                index,
            } => {
                let kind = self.nodes.get(node).ok_or(LiveError::UnknownNode)?.kind;
                if self.descendants(*node).contains(new_parent) || new_parent == node {
                    return Err(LiveError::TreeShape("a node cannot contain itself"));
                }
                self.check_parent(*new_parent, kind)?;
                let old_parent = self.nodes[node].parent;
                if let Some(old) = old_parent
                    && let Some(found) = self.nodes.get_mut(&old)
                {
                    found.children.retain(|child| child != node);
                }
                let children = &mut self
                    .nodes
                    .get_mut(new_parent)
                    .ok_or(LiveError::UnknownNode)?
                    .children;
                let at = (*index).min(children.len());
                children.insert(at, *node);
                self.nodes
                    .get_mut(node)
                    .ok_or(LiveError::UnknownNode)?
                    .parent = Some(*new_parent);
                vec![*node, *new_parent]
            }
            DeckOp::SetText { node, body } => {
                if !self.nodes.contains_key(node) {
                    return Err(LiveError::UnknownNode);
                }
                self.texts.insert(*node, body.clone());
                vec![*node]
            }
            DeckOp::SetRunMarks {
                node,
                paragraph,
                runs,
            } => {
                let body = self.texts.get_mut(node).ok_or(LiveError::UnknownNode)?;
                let found = body
                    .paragraphs
                    .iter_mut()
                    .find(|candidate| candidate.id == *paragraph)
                    .ok_or(LiveError::UnknownNode)?;
                found.runs = runs.clone();
                vec![*node]
            }
            DeckOp::SetGeometry { node, geometry } => {
                self.nodes
                    .get_mut(node)
                    .ok_or(LiveError::UnknownNode)?
                    .geometry = *geometry;
                vec![*node]
            }
            DeckOp::SetPreset { node, preset } => {
                let found = self.nodes.get_mut(node).ok_or(LiveError::UnknownNode)?;
                if !takes_preset(found.kind) {
                    return Err(LiveError::Invalid(ONLY_SHAPE_OR_PICTURE));
                }
                // The preset replaces a shape's custom geometry; the export's
                // effects name it. A picture's media stays its payload.
                if matches!(found.payload, Some(NodePayload::CustomGeometry { .. })) {
                    found.payload = None;
                }
                found.preset = Some(*preset);
                vec![*node]
            }
            DeckOp::SetPayload { node, payload } => {
                let found = self.nodes.get_mut(node).ok_or(LiveError::UnknownNode)?;
                if payload.kind() != found.kind {
                    return Err(LiveError::Invalid(
                        "the payload does not belong to the node kind",
                    ));
                }
                let bound = found.binding.is_some();
                let (settled, mut done) =
                    payload.settle(found.payload.as_ref(), bound, &self.opaque_parts)?;
                settled.check()?;
                // Edit Points draws the shape's own outline: its preset goes,
                // and a preset shape becomes a freeform.
                if matches!(settled, NodePayload::CustomGeometry { .. }) {
                    if !matches!(found.payload, Some(NodePayload::CustomGeometry { .. })) {
                        done.push(Conversion::ConvertedToFreeform);
                    }
                    found.preset = None;
                }
                // A written table that changes shape takes its grid's size at
                // export, as PowerPoint lays it out: its own extent clears.
                if bound
                    && let (Some(NodePayload::Table(was)), NodePayload::Table(now)) =
                        (&found.payload, &settled)
                    && was.shape() != now.shape()
                {
                    found.geometry.extent = None;
                }
                found.payload = Some(settled);
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: *node,
                    conversion,
                }));
                vec![*node]
            }
            DeckOp::EditTable { node, edits } => {
                let done = table_ops::edit_table(self, *node, edits)?;
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: *node,
                    conversion,
                }));
                vec![*node]
            }
            DeckOp::ReplaceOpaque {
                part,
                expected,
                replacement,
            } => {
                match self.opaque_parts.get(part) {
                    Some(current) if current == expected => {}
                    Some(_) => return Err(LiveError::Invalid("opaque source hash changed")),
                    None => return Err(LiveError::Invalid("unknown opaque part")),
                }
                self.opaque_parts.insert(part.clone(), *replacement);
                Vec::new()
            }
        };
        self.version += 1;
        Ok((affected, effects))
    }

    /// The tree rules of [`NodeKind::holds`].
    fn check_parent(&self, parent: NodeId, kind: NodeKind) -> Result<(), LiveError> {
        let found = self.nodes.get(&parent).ok_or(LiveError::UnknownNode)?;
        if found.kind.holds(kind) {
            Ok(())
        } else {
            Err(LiveError::TreeShape("parent cannot hold this node kind"))
        }
    }
}

/// The rebuildable attribution index: who made each visible thing, without
/// replaying history per inspection. Imported content resolves to no actor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionIndex {
    /// Node -> (actor, at) of its creation operation.
    pub created_by: BTreeMap<NodeId, (String, u64)>,
    /// Node -> contributing (actor, kind, at), causally last per actor/kind.
    pub contributions: BTreeMap<NodeId, Vec<(String, ChangeKind, u64)>>,
    /// Container -> actors with edits anywhere below it (cached summaries).
    pub descendant_actors: BTreeMap<NodeId, Vec<String>>,
}

impl AttributionIndex {
    /// Rebuild from the current deck and its stamped operation log. The log
    /// is the input; the index is a checkpoint that compaction may carry so
    /// authorship of visible content survives it.
    pub fn build(deck: &LiveDeck, log: &[StampedOp]) -> Self {
        let mut index = Self::default();
        // Minting is sequential, so the identities creation operations
        // produced are recoverable: the log's mints (its unnamed creations,
        // and the rows and columns its table edits inserted unnamed) are the
        // last mints below the deck's high-water mark, in log order.
        let creates: u64 = log.iter().map(|stamped| stamped.op.unnamed()).sum();
        let mut next_mint = deck.next_node.saturating_sub(creates);
        for stamped in log {
            let kind = stamped.op.kind();
            let created = match stamped.op {
                DeckOp::AddSlide { id: Some(id) } | DeckOp::AddNode { id: Some(id), .. } => {
                    Some(id)
                }
                DeckOp::AddSlide { id: None } | DeckOp::AddNode { id: None, .. } => {
                    let id = NodeId(next_mint);
                    next_mint += 1;
                    Some(id)
                }
                _ => {
                    next_mint += stamped.op.unnamed();
                    None
                }
            };
            let effective = created.or_else(|| stamped.op.target());
            if let Some(target) = effective {
                if kind == ChangeKind::Creation {
                    index
                        .created_by
                        .entry(target)
                        .or_insert_with(|| (stamped.made_by.clone(), stamped.at));
                }
                let entries = index.contributions.entry(target).or_default();
                entries.retain(|(actor, existing, _)| {
                    !(actor == &stamped.made_by && *existing == kind)
                });
                entries.push((stamped.made_by.clone(), kind, stamped.at));
            }
            // Summary actors on every ancestor of the touched node.
            if let Some(mut node) = effective
                && let Some(first) = deck.nodes.get(&node)
            {
                let mut cursor = first.parent;
                while let Some(parent) = cursor {
                    node = parent;
                    let actors = index.descendant_actors.entry(node).or_default();
                    if !actors.contains(&stamped.made_by) {
                        actors.push(stamped.made_by.clone());
                    }
                    cursor = deck.nodes.get(&node).and_then(|found| found.parent);
                }
            }
        }
        index
    }

    /// The actor that created `node`; `None` for imported content.
    pub fn creator(&self, node: NodeId) -> Option<&str> {
        self.created_by.get(&node).map(|(actor, _)| actor.as_str())
    }
}

/// A machine fork: the base it opened at and its actual stamped operations.
/// The fork joins a proposal by the shared proposal id; the proposer (and
/// its lineage) never settles it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckFork {
    pub proposal: String,
    pub proposer: String,
    /// The run that opened the fork, for the run approve-all scope.
    pub run_root: Option<String>,
    pub base_version: u64,
    pub base: LiveDeck,
    pub ops: Vec<StampedOp>,
}

impl LiveDeck {
    /// Open a fork at the current head. The agent writes the fork, never
    /// the live document.
    pub fn fork_at(&self, proposal: &str, proposer: &str, run_root: Option<&str>) -> DeckFork {
        DeckFork {
            proposal: proposal.to_owned(),
            proposer: proposer.to_owned(),
            run_root: run_root.map(str::to_owned),
            base_version: self.version,
            base: self.clone(),
            ops: Vec::new(),
        }
    }
}

impl DeckFork {
    pub fn record(&mut self, op: StampedOp) {
        self.ops.push(op);
    }

    /// The proposal state: the base with the fork's own operations applied.
    pub fn candidate(&self) -> Result<LiveDeck, LiveError> {
        let mut deck = self.base.clone();
        for op in &self.ops {
            deck.apply(op)?;
        }
        Ok(deck)
    }

    /// Nodes this fork touches that the head changed since the base: the
    /// units whose answers the race rule withdraws (ARCH-0075 section 4).
    pub fn stale_units(&self, head: &LiveDeck) -> Vec<NodeId> {
        let touched: BTreeSet<NodeId> = self.ops.iter().filter_map(|op| op.op.target()).collect();
        touched
            .into_iter()
            .filter(|node| unit_changed(&self.base, head, *node))
            .collect()
    }
}

/// Whether `node`'s own content differs between two states. A binding is
/// retained-package evidence, not content: an export's rebind changes none.
fn unit_changed(a: &LiveDeck, b: &LiveDeck, node: NodeId) -> bool {
    let content = |deck: &LiveDeck| {
        deck.nodes.get(&node).map(|found| DeckNode {
            binding: None,
            ..found.clone()
        })
    };
    content(a) != content(b) || a.texts.get(&node) != b.texts.get(&node)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMove {
    pub node: NodeId,
    pub old_parent: Option<NodeId>,
    pub new_parent: Option<NodeId>,
    pub old_index: Option<usize>,
    pub new_index: Option<usize>,
    /// A cross-slide move also changes relationship context.
    pub cross_slide: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueChange {
    pub part: String,
    pub base: Option<[u8; 32]>,
    pub proposal: Option<[u8; 32]>,
}

/// A concurrent-change conflict the merge must surface, never hide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conflict {
    /// Both sides moved one shape to different places.
    BothMoved { node: NodeId },
    /// One side deleted a node (or its ancestor) the other side edited.
    DeletedVsEdited { node: NodeId, deleted_by_head: bool },
    /// Both sides changed the same text body differently.
    TextVsText { node: NodeId },
    /// Reparent on one side, geometry on the other: local coordinates
    /// acquire another meaning.
    GeometryVsReparent { node: NodeId },
    /// Both sides replaced one opaque part with different bytes.
    BothReplacedOpaque { part: String },
    /// Both sides changed one node's preset or payload differently.
    PayloadVsPayload { node: NodeId },
    /// Both sides wrote one table cell differently.
    CellVsCell {
        node: NodeId,
        row: NodeId,
        column: NodeId,
    },
}

/// One relationship that differs between the head's export and the merged
/// candidate's: `before`/`after` are its target, `None` where it is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationshipChange {
    /// The source part (`""` for the package).
    pub source: String,
    pub id: String,
    pub kind: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// One slide's render identity: the hash of the slide and every part its
/// rendering depends on, in one export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideRender {
    pub slide: NodeId,
    pub part: String,
    pub fingerprint: [u8; 32],
}

/// One side of the review render pair, at a named version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderSide {
    pub version: u64,
    pub state_hash: [u8; 32],
    /// The export memo key the render input was projected under.
    pub export_key: [u8; 32],
    pub slides: Vec<SlideRender>,
}

/// The current head and the actual merged candidate, each at a named
/// version. The pair is stale once the head moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderPair {
    pub head: RenderSide,
    pub candidate: RenderSide,
    /// Slides whose render identity differs between the two, or that only
    /// one side holds.
    pub changed: Vec<NodeId>,
}

impl RenderPair {
    /// Whether `head` has moved past the version this pair rendered.
    pub fn stale(&self, head: &LiveDeck) -> bool {
        head.version != self.head.version || head.state_hash() != self.head.state_hash
    }
}

/// The three-way comparison of base, current head and proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckDiff {
    pub base_version: u64,
    pub head_version: u64,
    pub proposal_version: u64,
    pub added: Vec<NodeId>,
    pub removed: Vec<NodeId>,
    pub moved: Vec<NodeMove>,
    pub text_changed: Vec<NodeId>,
    pub formatting_changed: Vec<NodeId>,
    pub geometry_changed: Vec<NodeId>,
    /// Nodes whose preset or payload changed.
    pub payload_changed: Vec<NodeId>,
    pub opaque_changed: Vec<OpaqueChange>,
    /// Slides the proposal affects, including beyond the edited slide. Until
    /// render evidence is attached, any opaque replacement counts every slide;
    /// [`super::attach_evidence`] narrows it to the slides whose render
    /// identity the merged candidate changes.
    pub affected_slides: Vec<NodeId>,
    /// Nodes the head changed and the proposal did not: exactly what a
    /// switch would remove from the active head.
    pub head_only: Vec<NodeId>,
    pub conflicts: Vec<Conflict>,
    /// Relationship additions, removals and changed targets the merged
    /// candidate's export makes against the head's; empty until attached.
    pub relationships: Vec<RelationshipChange>,
    /// The review render pair; `None` until attached.
    pub renders: Option<RenderPair>,
}

pub(crate) fn slide_of(deck: &LiveDeck, mut node: NodeId) -> Option<NodeId> {
    loop {
        let found = deck.nodes.get(&node)?;
        if found.kind == NodeKind::Slide {
            return Some(node);
        }
        node = found.parent?;
    }
}

const ONLY_SHAPE_OR_PICTURE: &str = "only a shape or a picture takes a preset";

/// Whether a node of `kind` takes a preset: a shape's geometry, or the
/// shape a picture is cropped to (FIX 3696).
fn takes_preset(kind: NodeKind) -> bool {
    matches!(kind, NodeKind::Shape | NodeKind::Picture)
}

/// What a node is written as: its preset and payload.
fn written(node: &DeckNode) -> (Option<Preset>, &Option<NodePayload>) {
    (node.preset, &node.payload)
}

fn sibling_index(deck: &LiveDeck, node: NodeId) -> Option<usize> {
    let parent = deck.nodes.get(&node)?.parent?;
    deck.nodes
        .get(&parent)?
        .children
        .iter()
        .position(|child| *child == node)
}

/// The scratch-candidate check before any merge: the fork's actual
/// operations replayed onto the current head. Operations are never
/// cherry-picked and merging is never replaced with a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    /// The head version this preflight ran against; landing requires it.
    pub head_version: u64,
    pub candidate: LiveDeck,
    pub diff: DeckDiff,
    pub replay_refusals: Vec<String>,
    pub ok: bool,
}

/// The three ruled approve-all scopes. A finer scope is a later addition
/// and does not delay these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApproveScope {
    /// The named actor's bundle.
    ThisActor(String),
    /// The run root and everything its children proposed.
    ThisRunAndChildren(String),
    /// One item within the reviewed set, by its proposal id.
    OneItem(String),
}

impl ApproveScope {
    /// Whether this approval covers `fork`. Later forks never inherit an
    /// earlier approval: the scope names its set exactly.
    pub fn covers(&self, fork: &DeckFork) -> bool {
        match self {
            ApproveScope::ThisActor(actor) => fork.proposer == *actor,
            ApproveScope::ThisRunAndChildren(run) => fork.run_root.as_deref() == Some(run),
            ApproveScope::OneItem(proposal) => fork.proposal == *proposal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Landing {
    Merge,
    Switch,
}

/// The receipt a landing mints: decision scope, versions and actual
/// affected units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandingReceipt {
    pub proposal: String,
    pub proposer: String,
    pub settler: String,
    pub scope: ApproveScope,
    pub landing: Landing,
    pub automatic: bool,
    pub reviewed_version: u64,
    pub landed_version: u64,
    pub affected: Vec<NodeId>,
    /// Head-only nodes a switch removed; empty for a merge.
    pub switched_away: Vec<NodeId>,
}

/// Land a preflighted fork. The proposer never settles its own proposal,
/// and the head must be the one the preflight ran against.
pub fn land(
    head: &mut LiveDeck,
    fork: &DeckFork,
    report: &PreflightReport,
    settler: &str,
    scope: ApproveScope,
    landing: Landing,
    automatic: bool,
) -> Result<LandingReceipt, LiveError> {
    if settler == fork.proposer {
        return Err(LiveError::SelfSettle);
    }
    if head.version != report.head_version {
        return Err(LiveError::HeadAdvanced);
    }
    if !report.ok {
        return Err(LiveError::Invalid("preflight conflicts are unresolved"));
    }
    if !scope.covers(fork) {
        return Err(LiveError::Invalid(
            "the approval scope does not cover this fork",
        ));
    }
    let reviewed_version = head.version;
    let mut affected: BTreeSet<NodeId> = BTreeSet::new();
    affected.extend(report.diff.added.iter().copied());
    affected.extend(report.diff.removed.iter().copied());
    affected.extend(report.diff.moved.iter().map(|moved| moved.node));
    affected.extend(report.diff.text_changed.iter().copied());
    affected.extend(report.diff.formatting_changed.iter().copied());
    affected.extend(report.diff.geometry_changed.iter().copied());
    affected.extend(report.diff.payload_changed.iter().copied());
    let switched_away = match landing {
        Landing::Merge => {
            *head = report.candidate.clone();
            Vec::new()
        }
        Landing::Switch => {
            let mut proposal = fork.candidate()?;
            // Bindings and the hashes of opaque parts the proposal left alone
            // are evidence of the head's retained package, which a landed
            // export may have moved past the fork's base.
            for (id, node) in &mut proposal.nodes {
                if let Some(held) = head.nodes.get(id) {
                    node.binding = held.binding.clone();
                }
            }
            for (part, hash) in &mut proposal.opaque_parts {
                if fork.base.opaque_parts.get(part) == Some(hash)
                    && let Some(held) = head.opaque_parts.get(part)
                {
                    *hash = *held;
                }
            }
            let (version, next_node) = (head.version, head.next_node);
            proposal.id_marks.join(&head.id_marks);
            *head = proposal;
            // Identity allocation stays monotonic across the switch.
            head.next_node = head.next_node.max(next_node);
            head.version = version + 1;
            report.diff.head_only.clone()
        }
    };
    Ok(LandingReceipt {
        proposal: fork.proposal.clone(),
        proposer: fork.proposer.clone(),
        settler: settler.to_owned(),
        scope,
        landing,
        automatic,
        reviewed_version,
        landed_version: head.version,
        affected: affected.into_iter().collect(),
        switched_away,
    })
}
