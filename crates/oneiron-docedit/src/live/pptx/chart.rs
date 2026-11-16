//! A live chart's model (ARCH-0077, "One deck, one document": "Ordered
//! category and series ids over one dataset; caches and workbooks are
//! projections"): its families, where its data lives, and its series, an
//! ordered list of stable identities that a rename, a value or family
//! change and a move keep and a removal never frees. A series' identity is
//! the live model's, never its native `c:idx` or `c:order`, its place in the
//! chart part, or the workbook column it reads: a bound chart's binding
//! names which `c:ser` of its retained part each identity is
//! ([`SeriesBinding`]).

mod categories;
mod conflicts;
#[macro_use]
mod families;
mod special;

pub(crate) use categories::draws_categories;
pub use categories::{CategoryField, ChartCategories, ChartCategory, effective_categories};
pub(crate) use conflicts::conflicts;
pub use families::{BarDirection, BarShape, ChartPlot, ChartView, PlotGrouping, SizeRepresents};
pub use special::{OfPieType, SplitType, StockOrder, StockRoles, SurfaceBand};
pub(crate) use special::{lines_and_bars, surface};

use super::{Conflict, NodeId, NodePayload};
use crate::live::LiveError;
use serde::{Deserialize, Serialize};

/// The classic chart families the live deck reads and writes, live-born
/// charts included: the 2D families, their 3D forms, bubble charts, and
/// stock, surface and of-pie charts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChartKind {
    Bar,
    Line,
    Pie,
    Area,
    Scatter,
    Doughnut,
    Radar,
    #[serde(rename = "bar_3d")]
    Bar3D,
    #[serde(rename = "line_3d")]
    Line3D,
    #[serde(rename = "pie_3d")]
    Pie3D,
    #[serde(rename = "area_3d")]
    Area3D,
    /// Scatter-like: x values, values and a bubble size per point.
    Bubble,
    /// Prices by series ([`StockRoles`]): high, low and close, or open too.
    Stock,
    /// A 2D (contour) surface: heights over its categories and series.
    Surface,
    #[serde(rename = "surface_3d")]
    Surface3D,
    /// A pie of pie or bar of pie: some points drawn in a second plot.
    OfPie,
}

impl ChartKind {
    /// The plot element this family is written as.
    pub fn element(self) -> &'static str {
        match self {
            Self::Bar => "barChart",
            Self::Line => "lineChart",
            Self::Pie => "pieChart",
            Self::Area => "areaChart",
            Self::Scatter => "scatterChart",
            Self::Doughnut => "doughnutChart",
            Self::Radar => "radarChart",
            Self::Bar3D => "bar3DChart",
            Self::Line3D => "line3DChart",
            Self::Pie3D => "pie3DChart",
            Self::Area3D => "area3DChart",
            Self::Bubble => "bubbleChart",
            Self::Stock => "stockChart",
            Self::Surface => "surfaceChart",
            Self::Surface3D => "surface3DChart",
            Self::OfPie => "ofPieChart",
        }
    }

    /// Whether the family plots against axes (a pie, 3D pie, doughnut or
    /// of-pie does not).
    pub fn has_axes(self) -> bool {
        !matches!(self, Self::Pie | Self::Pie3D | Self::Doughnut | Self::OfPie)
    }
}

/// Where a chart's data lives.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ChartSource {
    /// The chart's own embedded workbook; caches are written with it.
    #[default]
    Workbook,
    /// Literal points in the chart part, with no workbook.
    Literal,
    /// Only the chart's caches: the data lives in a linked workbook, in
    /// another workbook, or in an embedded one the chart writer refuses
    /// (shared with another chart, or read by cells outside the series).
    /// Data written to it moves into a workbook of its own, as PowerPoint's
    /// Edit Data embeds it.
    Cached,
}

/// One series: its identity, its name, one value per category (or, in a
/// scatter or bubble plot, per x value), its plot family in a combo chart
/// and which plot of that family draws it, a scatter or bubble series' x
/// values (numbers, or text it draws by index), a bubble series' sizes, and
/// the categories it draws when they are its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChartSeries {
    /// Its identity within its chart. A series written with none, as a new
    /// one is, is named by its writer before the write is logged; a deck
    /// holds every series by identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<NodeId>,
    pub name: String,
    pub values: Vec<Option<serde_json::Number>>,
    /// In a chart of several plots (a combo), the family of the plot that
    /// draws this series.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<ChartKind>,
    /// A scatter or bubble series' x values, one per value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<Vec<Option<serde_json::Number>>>,
    /// A scatter or bubble series' x values when they are text (a
    /// `c:strRef` or `c:strLit` x slot), one label per value: it draws its
    /// points by index, 1 to n, as PowerPoint does, and a rewrite writes
    /// the labels back (FIX 9277). It holds no numeric `x` then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_labels: Option<Vec<Option<String>>>,
    /// In a chart holding more than one plot of its family, the nth of them
    /// (0 the first) that draws it: each plot keeps its own series
    /// (FIX 9377, 9278). The reader and settlement set it; `None` in a
    /// chart with one plot of its family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plot: Option<u32>,
    /// The logical plot's retained identity, named by the writer. Ordinal
    /// compaction and automatic views keep it; an explicit move takes the
    /// destination's identity. It is evidence, not a requested placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plot_id: Option<NodeId>,
    /// The categories it draws instead of the chart's: `None` draws the
    /// chart's, an empty set draws its points by index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<ChartCategories>,
    /// A bubble series' sizes, one per value; a missing or negative size
    /// is data, never zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bubble_size: Option<Vec<Option<serde_json::Number>>>,
    /// Whether a bubble series' bubbles are drawn in 3D.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bubble_3d: Option<bool>,
}

/// Which series identity each `c:ser` of a bound chart's retained part
/// holds, in the part's own order (its plots in document order, each plot's
/// series in document order), as the import read it or the last landed
/// export wrote it: retained evidence, never the order to write. The next
/// export finds each identity's own series, formatting and workbook cells by
/// it, and each category point's own `c:pt` by the category identities each
/// `c:ser` draws, in its point order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeriesBinding {
    pub series: Vec<NodeId>,
    /// Each `c:ser`'s category identities, by its place in `series`.
    #[serde(default)]
    pub categories: Vec<Vec<NodeId>>,
}

/// One edit to a chart by series and category identity: a series inserted,
/// deleted or moved, one field of one series written, a category point
/// inserted, deleted, moved or relabelled in the chart's set or a series'
/// own (`owner`, `None` the chart's), or the chart's family, categories or
/// data source. A series or point is placed after the one `after` names,
/// first when it names none, or last when its list no longer holds the one
/// named. An edit naming a series, a set or a point the chart no longer
/// holds does nothing: a concurrent delete wins, and an edit never brings
/// one back. A category series' values move with its points. The edited
/// chart settles as a whole chart written over it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChartEdit {
    /// A new series; `id` names it, or its writer names a fresh one.
    InsertSeries {
        #[serde(default)]
        id: Option<NodeId>,
        #[serde(default)]
        after: Option<NodeId>,
        #[serde(default)]
        name: String,
        #[serde(default)]
        values: Vec<Option<serde_json::Number>>,
        #[serde(default)]
        family: Option<ChartKind>,
        #[serde(default)]
        x: Option<Vec<Option<serde_json::Number>>>,
        /// A scatter or bubble series' x values as text, one label per
        /// value (FIX 10295).
        #[serde(default)]
        x_labels: Option<Vec<Option<String>>>,
        /// The nth plot of its family that draws it ([`ChartEdit::SetSeriesPlot`]);
        /// none places it as settlement does.
        #[serde(default)]
        plot: Option<u32>,
        /// Its own categories; none draws the chart's.
        #[serde(default)]
        categories: Option<ChartCategories>,
        /// A bubble series' sizes.
        #[serde(default)]
        bubble_size: Option<Vec<Option<serde_json::Number>>>,
        #[serde(default)]
        bubble_3d: Option<bool>,
    },
    /// A series goes; its identity is never used again in its chart.
    DeleteSeries {
        series: NodeId,
    },
    /// A series moves with its formatting, its cells and its values.
    MoveSeries {
        series: NodeId,
        #[serde(default)]
        after: Option<NodeId>,
    },
    SetSeriesName {
        series: NodeId,
        name: String,
    },
    SetSeriesValues {
        series: NodeId,
        values: Vec<Option<serde_json::Number>>,
    },
    /// The family of the plot that draws one series, as Change Series
    /// Chart Type sets it; none draws it in the chart's family.
    SetSeriesFamily {
        series: NodeId,
        #[serde(default)]
        family: Option<ChartKind>,
    },
    /// A scatter or bubble series' x values: numbers, or text labels it
    /// draws by index (FIX 10295). Numbers written replace text ones, and
    /// none writes no labels.
    SetSeriesX {
        series: NodeId,
        #[serde(default)]
        x: Option<Vec<Option<serde_json::Number>>>,
        #[serde(default)]
        x_labels: Option<Vec<Option<String>>>,
    },
    /// The plot of its family that draws one series, as Plot Series On
    /// Secondary Axis moves it (FIX 10295): the nth (0 the first) of the
    /// chart's plots of that family; one past them opens a new plot of the
    /// family after them, on its own axes, while the series' plot keeps
    /// another series. A plot every series of which moved away goes.
    SetSeriesPlot {
        series: NodeId,
        plot: u32,
    },
    /// A bubble series' sizes, one per value.
    SetSeriesBubbleSize {
        series: NodeId,
        #[serde(default)]
        bubble_size: Option<Vec<Option<serde_json::Number>>>,
    },
    /// Whether a bubble series' bubbles are drawn in 3D.
    #[serde(rename = "set_series_bubble_3d")]
    SetSeriesBubble3D {
        series: NodeId,
        #[serde(default)]
        bubble_3d: Option<bool>,
    },
    /// One plot's settings, the `nth` plot of its family, written over the
    /// settings the chart holds for it.
    SetPlot {
        plot: ChartPlot,
    },
    /// The chart's 3D view.
    SetView {
        #[serde(default)]
        view: Option<ChartView>,
    },
    /// The chart's family, as Change Chart Type sets it.
    SetFamily {
        family: ChartKind,
    },
    /// The chart's categories, which every series without its own draws.
    SetCategories {
        categories: ChartCategories,
    },
    /// One series' own categories; none draws the chart's again.
    SetSeriesCategories {
        series: NodeId,
        #[serde(default)]
        categories: Option<ChartCategories>,
    },
    /// A new category point, holding no value in the series that draw it;
    /// `id` names it, or its writer names a fresh one.
    InsertCategory {
        #[serde(default)]
        owner: Option<NodeId>,
        #[serde(default)]
        id: Option<NodeId>,
        #[serde(default)]
        after: Option<NodeId>,
        #[serde(default)]
        levels: Vec<Option<String>>,
    },
    /// A category point goes, with its value in each series that draws it.
    DeleteCategory {
        #[serde(default)]
        owner: Option<NodeId>,
        category: NodeId,
    },
    /// A category point moves with its values.
    MoveCategory {
        #[serde(default)]
        owner: Option<NodeId>,
        category: NodeId,
        #[serde(default)]
        after: Option<NodeId>,
    },
    /// One category point's labels, leaf level first.
    SetCategoryLevels {
        #[serde(default)]
        owner: Option<NodeId>,
        category: NodeId,
        levels: Vec<Option<String>>,
    },
    /// The identities, in order, the chart's settlement after these edits
    /// gives the category points it adds (a set grown to its longest series,
    /// x values turned to categories), named by the writer so every replay
    /// names them alike. Applying it changes nothing.
    ReserveCategories {
        ids: Vec<NodeId>,
    },
    /// The writer's identities for the new logical plots settlement adds,
    /// in plot order, so every replay retains the same continuity.
    ReservePlots {
        ids: Vec<NodeId>,
    },
    SetSource {
        source: ChartSource,
    },
}

/// The part of one series both sides of a fork wrote differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesField {
    Name,
    Values,
    Family,
    /// Both sides moved it to different plots of its family (FIX 12255).
    Plot,
    X,
    BubbleSize,
    #[serde(rename = "bubble_3d")]
    Bubble3D,
    /// Its own categories or the chart's, or the depth of its own.
    Categories,
    /// Both sides moved it, to different places.
    Order,
    /// One side deleted it and the other wrote it.
    Existence,
}

impl NodePayload {
    /// The chart as its export draws it: each category set padded to the
    /// longest category series that draws it, each such series' values to
    /// its set, and no x values on a category series, as an edit settles it.
    /// A chart concurrent writers joined is drawn so even where neither
    /// writer's settlement saw the other's; a settled chart, and any other
    /// payload, is drawn as it is.
    #[must_use]
    pub(crate) fn drawn(&self) -> NodePayload {
        let mut out = self.clone();
        if let Self::Chart {
            family,
            categories,
            series,
            plots,
            ..
        } = &mut out
        {
            categories::drawn(*family, categories, series);
            families::drawn(*family, series);
            let points = categories
                .ids()
                .into_iter()
                .chain(
                    series
                        .iter()
                        .filter_map(|line| line.categories.as_ref())
                        .flat_map(ChartCategories::ids),
                )
                .collect();
            special::drawn(*family, plots, series, &points);
        }
        out
    }
}

/// A chart's series fit the categories each draws: a category series holds
/// no more values than its set has points (a shorter one ends in missing
/// points; an empty set is points by index), and only a scatter series
/// carries x values, at least one per value. Its plots' fills and sizes
/// are ones a chart part holds.
pub(super) fn check(payload: &NodePayload) -> Result<(), LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        plots,
        ..
    } = payload
    else {
        return Ok(());
    };
    special::check(plots)?;
    for line in series {
        let set = effective_categories(categories, line);
        if !draws_categories(*family, line) {
            if line.x.as_ref().is_some_and(|x| x.len() < line.values.len())
                || line
                    .x_labels
                    .as_ref()
                    .is_some_and(|x| x.len() < line.values.len())
            {
                return Err(LiveError::Invalid(
                    "a scatter series holds more values than x values",
                ));
            }
        } else if line.x.is_some() || line.x_labels.is_some() {
            return Err(LiveError::Invalid("only a scatter series has x values"));
        } else if !set.is_empty() && line.values.len() > set.len() {
            return Err(LiveError::Invalid(
                "a chart series holds more values than there are categories",
            ));
        }
    }
    Ok(())
}
