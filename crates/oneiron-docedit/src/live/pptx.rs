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
use super::{diagram, points};
use crate::edit::{AssetRef, ConnectorPreset, Digest, IdMarks, Preset};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod attribution;
mod chart;
mod chart_ops;
mod deck_ops;
mod fork;
mod import;
mod merge;
mod table;
mod table_ops;

pub use attribution::AttributionIndex;
pub use chart::{
    BarDirection, BarShape, CategoryField, ChartCategories, ChartCategory, ChartEdit, ChartKind,
    ChartPlot, ChartSeries, ChartSource, ChartView, OfPieType, PlotGrouping, SeriesBinding,
    SeriesField, SizeRepresents, SplitType, StockOrder, StockRoles, SurfaceBand,
    effective_categories,
};
pub(crate) use chart::{draws_categories, lines_and_bars, surface};
pub use deck_ops::{ChangeKind, DeckOp, StampedOp};
pub use fork::{ApproveScope, DeckFork, Landing, LandingReceipt, PreflightReport, land};
pub(crate) use import::{geometry_of, text_body};
pub use merge::{diff, preflight, preflight_merged};
pub use table::{MergeFault, TableBinding, TableBody, TableEdit, TableMerge};
pub(crate) use table::{UNBOUND_GRID, positions};

/// Model identity for slides, shapes, paragraphs, a table's rows and
/// columns, and a chart's series. The root is `NodeId(0)`.
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
    /// A chart frame's series as its retained chart part holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series: Option<SeriesBinding>,
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
    /// A classic chart: its categories, by identity, each series one value
    /// per category of the set it draws (the chart's, or its own; `None` is
    /// a missing point), or a scatter or bubble series one value per x
    /// value; each plot's own settings, by its family and place; and its 3D
    /// view.
    Chart {
        family: ChartKind,
        categories: ChartCategories,
        series: Vec<ChartSeries>,
        /// Where the data lives; a live-born chart's is its own workbook.
        #[serde(default)]
        source: ChartSource,
        /// Each plot's settings the model holds, the nth plot of a family
        /// by itself ([`ChartPlot`]); a plot none names keeps its own.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        plots: Vec<ChartPlot>,
        /// The chart's 3D view; `None` keeps the one it holds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        view: Option<ChartView>,
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

    /// A chart's series fit the categories each draws ([`chart::check`]).
    pub fn check(&self) -> Result<(), LiveError> {
        chart::check(self)
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
    /// Both sides wrote one chart series' field differently, moved it to
    /// different places, or one deleted it and the other wrote it.
    SeriesVsSeries {
        node: NodeId,
        series: NodeId,
        field: SeriesField,
    },
    /// Both sides relabelled one category point of a chart's set (`owner`
    /// `None`) or of one series' own differently, moved it to different
    /// places, or one deleted it and the other wrote it.
    CategoryVsCategory {
        node: NodeId,
        owner: Option<NodeId>,
        category: NodeId,
        field: CategoryField,
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
    /// What a switch would remove from the active head: every node whose
    /// head work since the base the proposal does not hold, an addition, a
    /// removal undone, or a changed field (merge::switch_losses, FIX 8592).
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
