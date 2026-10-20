//! A live chart's model (ARCH-0077, "One deck, one document": "Ordered
//! category and series ids over one dataset; caches and workbooks are
//! projections"): its families, where its data lives, and its series, an
//! ordered list of stable identities that a rename, a value or family
//! change and a move keep and a removal never frees. A series' identity is
//! the live model's, never its native `c:idx` or `c:order`, its place in the
//! chart part, or the workbook column it reads: a bound chart's binding
//! names which `c:ser` of its retained part each identity is
//! ([`SeriesBinding`]).

use super::{Conflict, DeckNode, NodeId, NodePayload};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

/// One series: its identity, its name, one value per category (or, in a
/// scatter plot, per x value), its plot family in a combo chart, and a
/// scatter series' x values.
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
    /// A scatter series' x values, one per value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<Vec<Option<serde_json::Number>>>,
}

/// Which series identity each `c:ser` of a bound chart's retained part
/// holds, in the part's own order (its plots in document order, each plot's
/// series in document order), as the import read it or the last landed
/// export wrote it: retained evidence, never the order to write. The next
/// export finds each identity's own series, formatting and workbook cells by
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeriesBinding {
    pub series: Vec<NodeId>,
}

/// One edit to a chart by series identity: a series inserted, deleted or
/// moved, one field of one series written, or the chart's family,
/// categories or data source. A series is placed after the one `after`
/// names, first when it names none, or last when the chart no longer holds
/// the one named. An edit naming a series the chart no longer holds does
/// nothing: a concurrent delete wins, and an edit never brings a series
/// back. The edited chart settles as a whole chart written over it does.
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
    /// A scatter series' x values.
    SetSeriesX {
        series: NodeId,
        #[serde(default)]
        x: Option<Vec<Option<serde_json::Number>>>,
    },
    /// The chart's family, as Change Chart Type sets it.
    SetFamily {
        family: ChartKind,
    },
    SetCategories {
        categories: Vec<String>,
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
    X,
    /// Both sides moved it, to different places.
    Order,
    /// One side deleted it and the other wrote it.
    Existence,
}

impl NodePayload {
    /// The chart as its export draws it: its categories padded to its
    /// longest category series, and no x values on a category series, as an
    /// edit settles it. A chart concurrent writers joined is drawn so even
    /// where neither writer's settlement saw the other's; a settled chart,
    /// and any other payload, is drawn as it is.
    #[must_use]
    pub(crate) fn drawn(&self) -> NodePayload {
        let mut out = self.clone();
        if let Self::Chart {
            family,
            categories,
            series,
            ..
        } = &mut out
        {
            let chart_family = *family;
            let category =
                |line: &ChartSeries| line.family.unwrap_or(chart_family) != ChartKind::Scatter;
            let longest = series
                .iter()
                .filter(|line| category(line))
                .map(|line| line.values.len())
                .max()
                .unwrap_or(0);
            if !categories.is_empty() && categories.len() < longest {
                categories.resize(longest, String::new());
            }
            for line in &mut *series {
                if category(line) {
                    line.x = None;
                }
            }
        }
        out
    }
}

/// The conflicts of a chart both sides of a fork wrote, when the base, the
/// head and the proposal all hold a chart: one series' name, values, family
/// or x values both sides wrote differently, one series both sides moved to
/// different places (among the series all three hold), or one series one
/// side deleted and the other wrote ([`Conflict::SeriesVsSeries`]); and the
/// chart's family, categories or data source both sides wrote differently
/// ([`Conflict::PayloadVsPayload`]). Series inserted, deleted, moved or
/// written by one side only, and different fields of one series, join
/// without conflict. `None` when one of them holds no chart.
pub(crate) fn conflicts(
    node: NodeId,
    base: &DeckNode,
    head: &DeckNode,
    proposal: &DeckNode,
) -> Option<Vec<Conflict>> {
    let (
        Some(NodePayload::Chart {
            family: base_family,
            categories: base_categories,
            series: base_series,
            source: base_source,
        }),
        Some(NodePayload::Chart {
            family: head_family,
            categories: head_categories,
            series: head_series,
            source: head_source,
        }),
        Some(NodePayload::Chart {
            family: proposal_family,
            categories: proposal_categories,
            series: proposal_series,
            source: proposal_source,
        }),
    ) = (&base.payload, &head.payload, &proposal.payload)
    else {
        return None;
    };
    if base.preset != head.preset || base.preset != proposal.preset {
        return None;
    }
    let mut out = Vec::new();
    if competing(base_family, head_family, proposal_family)
        || competing(base_categories, head_categories, proposal_categories)
        || competing(base_source, head_source, proposal_source)
    {
        out.push(Conflict::PayloadVsPayload { node });
    }
    let find = |lines: &[ChartSeries], id: NodeId| -> Option<ChartSeries> {
        lines.iter().find(|line| line.id == Some(id)).cloned()
    };
    let held = |lines: &[ChartSeries]| -> BTreeSet<NodeId> {
        lines.iter().filter_map(|line| line.id).collect()
    };
    let (in_head, in_proposal) = (held(head_series), held(proposal_series));
    // The series before `id` among those all three hold: where a side put it.
    let before = |lines: &[ChartSeries], id: NodeId| -> Option<NodeId> {
        lines
            .iter()
            .filter_map(|line| line.id)
            .filter(|other| in_head.contains(other) && in_proposal.contains(other))
            .take_while(|other| *other != id)
            .last()
    };
    for was in base_series {
        let Some(id) = was.id else {
            continue;
        };
        let series = |field| Conflict::SeriesVsSeries {
            node,
            series: id,
            field,
        };
        match (find(head_series, id), find(proposal_series, id)) {
            (Some(head), Some(proposal)) => {
                for (field, both) in [
                    (
                        SeriesField::Name,
                        competing(&was.name, &head.name, &proposal.name),
                    ),
                    (
                        SeriesField::Values,
                        competing(&was.values, &head.values, &proposal.values),
                    ),
                    (
                        SeriesField::Family,
                        competing(&was.family, &head.family, &proposal.family),
                    ),
                    (SeriesField::X, competing(&was.x, &head.x, &proposal.x)),
                ] {
                    if both {
                        out.push(series(field));
                    }
                }
                if competing(
                    &before(base_series, id),
                    &before(head_series, id),
                    &before(proposal_series, id),
                ) {
                    out.push(series(SeriesField::Order));
                }
            }
            (None, Some(written)) | (Some(written), None) if written != *was => {
                out.push(series(SeriesField::Existence));
            }
            _ => {}
        }
    }
    Some(out)
}

/// Whether both sides wrote one value differently.
fn competing<T: PartialEq>(base: &T, head: &T, proposal: &T) -> bool {
    base != head && base != proposal && head != proposal
}
