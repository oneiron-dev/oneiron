//! A live chart's model: its families, where its data lives, and its
//! series (ARCH-0077: caches and workbooks are projections of one dataset).

use serde::{Deserialize, Serialize};

/// The classic chart families the live deck reads and writes, live-born
/// charts included.
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
        }
    }

    /// Whether the family plots against axes (a pie or doughnut does not).
    pub fn has_axes(self) -> bool {
        !matches!(self, Self::Pie | Self::Doughnut)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChartSeries {
    pub name: String,
    pub values: Vec<Option<serde_json::Number>>,
    /// In a chart of several plots (a combo), the family of the plot that
    /// draws this series.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<ChartKind>,
    /// A scatter series' x values, one per value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<Vec<Option<serde_json::Number>>>,
}
