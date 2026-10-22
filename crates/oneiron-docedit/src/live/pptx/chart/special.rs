//! A live chart's stock, surface and of-pie settings (OF-510, FIX 3493 D9c),
//! held on each plot's own [`ChartPlot`]: a stock plot's prices by series
//! identity ([`StockRoles`]), never by name, column or place; a surface
//! plot's bands ([`SurfaceBand`]); an of-pie plot's second plot and the
//! category points split into it, by category identity. A surface plot's
//! heights are its series' values over their categories, and an of-pie
//! plot's second plot a view of its one dataset: neither is a second store.

use super::{ChartKind, ChartPlot, ChartSeries, NodeId};
use crate::live::LiveError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Which prices a stock plot draws, in its series order: high, low and
/// close, or open, high, low and close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StockOrder {
    Hlc,
    Ohlc,
}

/// The series a stock plot draws as each price, by series identity: a
/// moved series keeps its price, a renamed or rewritten one too. A price
/// no series draws is empty (`None`), never filled with made-up values;
/// `open` is a price of an OHLC plot only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StockRoles {
    pub order: StockOrder,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close: Option<NodeId>,
}

impl StockRoles {
    /// No series for any price of `order`.
    pub(crate) fn empty(order: StockOrder) -> Self {
        Self {
            order,
            open: None,
            high: None,
            low: None,
            close: None,
        }
    }

    /// The order a stock plot of `count` series takes where the model names
    /// none: open, high, low and close from four series on, else high, low
    /// and close (CALLS, D9c stock roles).
    pub(crate) fn order_for(count: usize) -> StockOrder {
        if count >= 4 {
            StockOrder::Ohlc
        } else {
            StockOrder::Hlc
        }
    }

    /// Its prices in plot order, each by name: open first in an OHLC plot.
    pub(crate) fn slots(&self) -> Vec<(&'static str, Option<NodeId>)> {
        let mut out = Vec::with_capacity(4);
        if self.order == StockOrder::Ohlc {
            out.push(("open", self.open));
        }
        out.extend([
            ("high", self.high),
            ("low", self.low),
            ("close", self.close),
        ]);
        out
    }

    /// Its prices in plot order, to fill.
    pub(crate) fn slots_mut(&mut self) -> Vec<&mut Option<NodeId>> {
        let Self {
            order,
            open,
            high,
            low,
            close,
        } = self;
        let mut out = Vec::with_capacity(4);
        if *order == StockOrder::Ohlc {
            out.push(open);
        } else {
            *open = None;
        }
        out.extend([high, low, close]);
        out
    }

    /// The series it binds, in plot order.
    pub(crate) fn drawn(&self) -> Vec<NodeId> {
        self.slots().into_iter().filter_map(|(_, id)| id).collect()
    }

    /// The prices no series draws.
    pub(crate) fn missing(&self) -> Vec<String> {
        self.slots()
            .into_iter()
            .filter(|(_, id)| id.is_none())
            .map(|(name, _)| name.to_owned())
            .collect()
    }

    /// Where `id` stands in plot order, when it draws a price.
    pub(crate) fn rank(&self, id: Option<NodeId>) -> Option<usize> {
        let id = id?;
        self.slots().iter().position(|(_, at)| *at == Some(id))
    }
}

/// An of-pie plot's second plot: a pie (pie of pie) or a bar (bar of pie).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfPieType {
    Pie,
    Bar,
}

tokens!(OfPieType {
    Pie = "pie",
    Bar = "bar"
});

/// How an of-pie plot picks the points its second plot draws: by the
/// application's choice, by `custom_split`, by percentage, by position
/// from the end, or by value below `split_pos`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SplitType {
    Auto,
    Cust,
    Percent,
    Pos,
    Val,
}

tokens!(SplitType {
    Auto = "auto",
    Cust = "cust",
    Percent = "percent",
    Pos = "pos",
    Val = "val",
});

/// One band of a surface plot (its `c:bandFmt`), by its index: the fill
/// the model sets, as six hex digits. A band the model does not list keeps
/// its own formatting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SurfaceBand {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill: Option<String>,
}

/// Whether `family` is a surface family, 2D (contour) or 3D.
pub(crate) fn surface(family: ChartKind) -> bool {
    matches!(family, ChartKind::Surface | ChartKind::Surface3D)
}

/// Whether `family` holds high-low lines and up/down bars.
pub(crate) fn lines_and_bars(family: ChartKind) -> bool {
    matches!(family, ChartKind::Line | ChartKind::Stock)
}

/// The special settings of `plot` the `kind` plot holds, copied into
/// `out`, and the names (as its chart part names them) of those it drops.
pub(super) fn fit(plot: &ChartPlot, kind: ChartKind, out: &mut ChartPlot) -> Vec<&'static str> {
    let stock = kind == ChartKind::Stock;
    let lines = lines_and_bars(kind);
    let surface = surface(kind);
    let of_pie = kind == ChartKind::OfPie;
    out.stock = plot.stock.filter(|_| stock);
    out.hi_low_lines = plot.hi_low_lines.filter(|_| lines);
    out.up_down_bars = plot.up_down_bars.filter(|_| lines);
    out.up_down_gap_width = plot.up_down_gap_width.filter(|_| lines);
    out.up_fill = plot.up_fill.clone().filter(|_| lines);
    out.down_fill = plot.down_fill.clone().filter(|_| lines);
    out.wireframe = plot.wireframe.filter(|_| surface);
    out.bands = plot.bands.clone().filter(|_| surface);
    out.of_pie_type = plot.of_pie_type.filter(|_| of_pie);
    out.split_type = plot.split_type.filter(|_| of_pie);
    out.split_pos = plot.split_pos.clone().filter(|_| of_pie);
    out.custom_split = plot.custom_split.clone().filter(|_| of_pie);
    out.second_pie_size = plot.second_pie_size.filter(|_| of_pie);
    out.gap_width = plot.gap_width.filter(|_| of_pie);
    out.ser_lines = plot.ser_lines.filter(|_| of_pie);
    let bars = plot.up_down_bars.is_some()
        || plot.up_down_gap_width.is_some()
        || plot.up_fill.is_some()
        || plot.down_fill.is_some();
    [
        ("stockRoles", plot.stock.is_some() && !stock),
        ("hiLowLines", plot.hi_low_lines.is_some() && !lines),
        ("upDownBars", bars && !lines),
        ("wireframe", plot.wireframe.is_some() && !surface),
        ("bandFmts", plot.bands.is_some() && !surface),
        ("ofPieType", plot.of_pie_type.is_some() && !of_pie),
        ("splitType", plot.split_type.is_some() && !of_pie),
        ("splitPos", plot.split_pos.is_some() && !of_pie),
        ("custSplit", plot.custom_split.is_some() && !of_pie),
        ("secondPieSize", plot.second_pie_size.is_some() && !of_pie),
        ("gapWidth", plot.gap_width.is_some() && !of_pie),
        ("serLines", plot.ser_lines.is_some() && !of_pie),
    ]
    .into_iter()
    .filter(|&(_, dropped)| dropped)
    .map(|(name, _)| name)
    .collect()
}

/// A fill a chart part can write: six hex digits.
fn fill(value: Option<&String>) -> Result<(), LiveError> {
    match value {
        Some(rgb) if rgb.len() != 6 || !rgb.bytes().all(|byte| byte.is_ascii_hexdigit()) => Err(
            LiveError::Invalid("a chart fill is six hex digits (RRGGBB)"),
        ),
        _ => Ok(()),
    }
}

/// The special settings a chart part can hold: fills of six hex digits, a
/// gap of 0 to 500 percent, a second plot of 5 to 200 percent of the first.
pub(super) fn check(plots: &[ChartPlot]) -> Result<(), LiveError> {
    for plot in plots {
        fill(plot.up_fill.as_ref())?;
        fill(plot.down_fill.as_ref())?;
        for band in plot.bands.iter().flatten() {
            fill(band.fill.as_ref())?;
        }
        if plot
            .up_down_gap_width
            .into_iter()
            .chain(plot.gap_width)
            .any(|gap| gap > 500)
        {
            return Err(LiveError::Invalid("a chart gap width is 0 to 500 percent"));
        }
        if plot
            .second_pie_size
            .is_some_and(|size| !(5..=200).contains(&size))
        {
            return Err(LiveError::Invalid(
                "an of-pie plot's second plot is 5 to 200 percent of its first",
            ));
        }
    }
    Ok(())
}

/// The plots' stock prices and custom splits as a chart concurrent writers
/// joined draws them: a price whose series the chart no longer draws in a
/// stock plot is empty, a split point no set holds goes, and each stock
/// plot's series stand in its price order among the places they hold.
pub(super) fn drawn(
    family: ChartKind,
    plots: &mut [ChartPlot],
    series: &mut [ChartSeries],
    points: &BTreeSet<NodeId>,
) {
    let stocks: BTreeSet<NodeId> = series
        .iter()
        .filter(|line| line.family.unwrap_or(family) == ChartKind::Stock)
        .filter_map(|line| line.id)
        .collect();
    for plot in plots.iter_mut() {
        if let Some(roles) = &mut plot.stock {
            for slot in roles.slots_mut() {
                if slot.is_some_and(|id| !stocks.contains(&id)) {
                    *slot = None;
                }
            }
        }
        if let Some(split) = &mut plot.custom_split {
            split.retain(|id| points.contains(id));
        }
    }
    for roles in plots.iter().filter_map(|plot| plot.stock) {
        let places: Vec<usize> = (0..series.len())
            .filter(|&at| roles.rank(series[at].id).is_some())
            .collect();
        let mut ranked: Vec<ChartSeries> = places.iter().map(|&at| series[at].clone()).collect();
        ranked.sort_by_key(|line| roles.rank(line.id));
        for (at, line) in places.into_iter().zip(ranked) {
            series[at] = line;
        }
    }
}
