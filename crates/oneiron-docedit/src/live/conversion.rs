//! What a deck edit or export did PowerPoint's way, named on its receipt
//! (OF-510; the Office ruling of 10-18).

use super::pptx::{ChartKind, ChartSource};
use crate::edit::Effect;
use serde::{Deserialize, Serialize};

/// What a deck edit did PowerPoint's way, named on its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Conversion {
    /// A plot changed family, as Change Chart Type does. Between a category
    /// and a scatter family the categories became x values or the x values
    /// categories, and the x axis turned with them.
    ChartTypeChanged { from: ChartKind, to: ChartKind },
    /// A series is drawn in a family the chart had no plot for, so a new
    /// plot draws it, as Change Series Chart Type makes one.
    PlotAdded { family: ChartKind },
    /// A plot no series is drawn in any more went.
    PlotDropped { family: ChartKind },
    /// The series are listed plot by plot, as a chart lists them.
    SeriesRegrouped,
    /// The categories became the scatter series' x values, numbered 1 to n
    /// when they are text (`numbered`).
    CategoriesBecameX { numbered: bool },
    /// The first category series' x values became the categories.
    XBecameCategories,
    /// These category series carried x values a category plot does not
    /// draw; they were dropped.
    XDropped { series: Vec<String> },
    /// A chart of scatter plots only takes no categories.
    CategoriesDropped,
    /// The categories were padded with empty labels to `count`, the longest
    /// category series.
    CategoriesPadded { count: usize },
    /// The chart's link to external data was dropped, and its data embedded
    /// in a workbook of its own, as PowerPoint's Edit Data does.
    ExternalDataEmbedded,
    /// The chart read a workbook another chart shares, or cells outside its
    /// series; its data now lives in a workbook of its own.
    WorkbookUnshared,
    /// Literal chart data was embedded in a workbook.
    LiteralDataEmbedded,
    /// A new chart's data lives in its own workbook, as PowerPoint writes
    /// every chart it inserts.
    NewChartEmbedded,
    /// The chart keeps where its data lives: an edit makes no `asked` data.
    SourceKept {
        kept: ChartSource,
        asked: ChartSource,
    },
    /// A title or label linked to a cell keeps its text, unlinked.
    TitleLinkDropped,
    /// This many SmartArt nodes' text was written into the data part and
    /// the shapes its drawing draws for them.
    SmartArtTextWritten { nodes: u32 },
    /// An imported picture shows this media part the deck holds.
    HeldMediaShown { part: String },
    /// A reshaped table's frame took its grid's size.
    TableFrameFitted { extent: (i64, i64) },
    /// A written table's ragged rows (and header) were padded with empty
    /// cells to the widest row, `columns` wide: a table is a grid.
    TableRowsPadded { columns: usize },
    /// A preset shape given paths became a freeform, as Edit Points
    /// converts it.
    ConvertedToFreeform,
    /// This many paths were written over the shape's outline.
    PointsEdited { paths: u32 },
    /// The freeform's connection sites were redrawn at its new vertices, as
    /// Edit Points places them.
    VertexSitesRedrawn { sites: u32 },
    /// The text rectangle named a guide the edit dropped; it spans the
    /// shape again.
    TextRectReset,
    /// SmartArt levels were clamped so each node sits at most one level
    /// below the node before it, as the text pane indents.
    SmartArtLevelsClamped { nodes: u32 },
    /// SmartArt nodes were added or removed, or moved to another parent or
    /// place: the diagram's points and connections were rewritten.
    SmartArtRestructured { added: u32, removed: u32 },
    /// The SmartArt's cached drawing went; PowerPoint lays the diagram out
    /// again from its layout when it opens the deck.
    SmartArtDrawingDropped,
    /// A new SmartArt of this many nodes, laid out by the engine's own
    /// outline list (no Office layout file is copied).
    SmartArtBorn { nodes: u32 },
    /// The former embedded workbook no part reads any more was removed.
    WorkbookPruned { part: String },
    /// This many data labels that showed a range of the former workbook's
    /// cells now carry that text themselves.
    LabelRangesUnlinked { labels: u32 },
}

fn family_name(kind: ChartKind) -> &'static str {
    match kind {
        ChartKind::Bar => "bar",
        ChartKind::Line => "line",
        ChartKind::Pie => "pie",
        ChartKind::Area => "area",
        ChartKind::Scatter => "scatter",
        ChartKind::Doughnut => "doughnut",
        ChartKind::Radar => "radar",
    }
}

fn source_name(source: ChartSource) -> &'static str {
    match source {
        ChartSource::Workbook => "embedded workbook",
        ChartSource::Literal => "literal",
        ChartSource::Cached => "linked",
    }
}

impl Conversion {
    /// The receipt's sentence for it.
    pub fn describe(&self) -> String {
        match self {
            Self::ChartTypeChanged { from, to } => format!(
                "chart type changed from {} to {}",
                family_name(*from),
                family_name(*to)
            ),
            Self::PlotAdded { family } => {
                format!("a {} plot added for its series", family_name(*family))
            }
            Self::PlotDropped { family } => format!(
                "the {} plot dropped: no series is drawn in it",
                family_name(*family)
            ),
            Self::SeriesRegrouped => "series listed plot by plot".to_owned(),
            Self::CategoriesBecameX { numbered: false } => "categories became x values".to_owned(),
            Self::CategoriesBecameX { numbered: true } => {
                "text categories became x values 1 to n".to_owned()
            }
            Self::XBecameCategories => "x values became categories".to_owned(),
            Self::XDropped { series } => {
                format!(
                    "x values dropped from category series {}",
                    series.join(", ")
                )
            }
            Self::CategoriesDropped => {
                "categories dropped: a scatter chart plots x values".to_owned()
            }
            Self::CategoriesPadded { count } => {
                format!("categories padded with empty labels to {count}")
            }
            Self::ExternalDataEmbedded => "link to external data dropped; data embedded".to_owned(),
            Self::WorkbookUnshared => "chart data moved to a workbook of its own".to_owned(),
            Self::LiteralDataEmbedded => "literal chart data embedded in a workbook".to_owned(),
            Self::NewChartEmbedded => {
                "the new chart's data embedded in its own workbook".to_owned()
            }
            Self::SourceKept { kept, asked } => format!(
                "chart data stays {}: an edit makes no {} data",
                source_name(*kept),
                source_name(*asked)
            ),
            Self::TitleLinkDropped => {
                "a title linked to a cell keeps its text, unlinked".to_owned()
            }
            Self::SmartArtTextWritten { nodes } => {
                format!("SmartArt text written for {nodes} node(s)")
            }
            Self::HeldMediaShown { part } => format!("picture shows held media {part}"),
            Self::TableFrameFitted { extent: (cx, cy) } => {
                format!("table frame fitted to its grid: {cx} x {cy} EMU")
            }
            Self::TableRowsPadded { columns } => {
                format!("table rows padded with empty cells to {columns} column(s)")
            }
            Self::ConvertedToFreeform => {
                "the shape became a freeform to take its points".to_owned()
            }
            Self::PointsEdited { paths } => format!("points written: {paths} path(s)"),
            Self::VertexSitesRedrawn { sites } => {
                format!("connection sites redrawn at {sites} vertices")
            }
            Self::TextRectReset => {
                "the text area named a dropped guide; it spans the shape".to_owned()
            }
            Self::SmartArtLevelsClamped { nodes } => {
                format!("{nodes} SmartArt node level(s) clamped to one below the node before")
            }
            Self::SmartArtRestructured { added, removed } => format!(
                "SmartArt nodes rewritten: {added} added, {removed} removed, the rest kept in place"
            ),
            Self::SmartArtDrawingDropped => {
                "SmartArt drawing dropped; PowerPoint lays the diagram out again".to_owned()
            }
            Self::SmartArtBorn { nodes } => {
                format!("new SmartArt of {nodes} node(s) laid out as the engine's outline list")
            }
            Self::WorkbookPruned { part } => {
                format!("former workbook {part} removed: nothing reads it")
            }
            Self::LabelRangesUnlinked { labels } => {
                format!("{labels} data label(s) keep their cell-range text, unlinked")
            }
        }
    }
}

/// An edit's or an export's effect as its receipt names it.
pub fn effect_receipt(effect: &Effect) -> String {
    match effect {
        Effect::Converted { node, conversion } => {
            format!("node {}: {}", node.0, conversion.describe())
        }
        Effect::CustomGeometryReplaced => "custom geometry replaced by a preset".to_owned(),
        Effect::InheritedGeometryOwned => {
            "inherited geometry replaced by the shape's own preset".to_owned()
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}
