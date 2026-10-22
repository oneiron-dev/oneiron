//! A live chart's families and their settings (OF-510, FIX 3493 D9b):
//! which families draw x values (scatter and bubble) and which are drawn in
//! three dimensions, the depth axis a 3D plot stands its series on, each
//! plot's own settings ([`ChartPlot`], the nth plot of its family, so
//! repeated plots and the plots of a combo keep their own), and the chart's
//! 3D view ([`ChartView`]). A setting `None` is one the model does not set:
//! a held plot or view keeps its bytes, a new one takes its family's
//! default.

use super::special::{self, OfPieType, SplitType, StockRoles, SurfaceBand};
use super::{ChartKind, ChartSeries, NodeId};
use serde::{Deserialize, Serialize};

impl ChartKind {
    /// Whether the family draws x values, not categories: a scatter or a
    /// bubble plot.
    pub fn draws_x(self) -> bool {
        matches!(self, Self::Scatter | Self::Bubble)
    }

    /// Whether the family is drawn in three dimensions.
    pub fn is_3d(self) -> bool {
        matches!(
            self,
            Self::Bar3D | Self::Line3D | Self::Pie3D | Self::Area3D | Self::Surface3D
        )
    }

    /// Whether a plot of this family, laid out as `grouping`, stands its
    /// series on a depth (series) axis as well: a 3D line plot and a
    /// surface plot (2D or 3D) always, a 3D bar or area plot whose series
    /// stand one behind another (`standard`, an area plot's default), never
    /// a 3D pie.
    pub fn depth_axis(self, grouping: Option<PlotGrouping>) -> bool {
        match self {
            Self::Line3D | Self::Surface | Self::Surface3D => true,
            Self::Area3D => grouping.is_none_or(|grouping| grouping == PlotGrouping::Standard),
            Self::Bar3D => grouping == Some(PlotGrouping::Standard),
            _ => false,
        }
    }
}

macro_rules! tokens {
    ($name:ident { $($variant:ident = $token:literal),+ $(,)? }) => {
        impl $name {
            /// Its value in a chart part.
            pub(crate) fn token(self) -> &'static str {
                match self {
                    $(Self::$variant => $token),+
                }
            }

            /// The setting a chart part's value names.
            pub(crate) fn parse(token: &str) -> Option<Self> {
                match token.trim() {
                    $($token => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

/// Which way a bar plot's bars run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BarDirection {
    /// Horizontal bars.
    Bar,
    /// Vertical columns.
    Col,
}

tokens!(BarDirection { Bar = "bar", Col = "col" });

/// How a plot lays its series out: side by side (`clustered`, bar plots
/// only), one behind another (`standard`), stacked, or stacked to 100%.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlotGrouping {
    Standard,
    Clustered,
    Stacked,
    PercentStacked,
}

tokens!(PlotGrouping {
    Standard = "standard",
    Clustered = "clustered",
    Stacked = "stacked",
    PercentStacked = "percentStacked",
});

/// A 3D bar plot's bar shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BarShape {
    Box,
    Cone,
    ConeToMax,
    Cylinder,
    Pyramid,
    PyramidToMax,
}

tokens!(BarShape {
    Box = "box",
    Cone = "cone",
    ConeToMax = "coneToMax",
    Cylinder = "cylinder",
    Pyramid = "pyramid",
    PyramidToMax = "pyramidToMax",
});

/// What a bubble's size scales: its area or its width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SizeRepresents {
    Area,
    Width,
}

tokens!(SizeRepresents {
    Area = "area",
    Width = "w",
});

/// One plot's own settings: the `nth` plot (0 the first) of `family`, in
/// the chart's plot order, so two plots of one family each keep theirs.
/// Each setting applies to the families that hold it ([`ChartPlot::fit`]);
/// `None` keeps what the plot holds, or gives a new plot its family's
/// default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChartPlot {
    pub family: ChartKind,
    #[serde(default)]
    pub nth: u32,
    /// Bar plots, 2D and 3D: bars or columns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bar_dir: Option<BarDirection>,
    /// Bar, line and area plots, 2D and 3D.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouping: Option<PlotGrouping>,
    /// 3D bar plots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<BarShape>,
    /// 3D bar, line and area plots: the depth between series, as a
    /// percentage of a bar's width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_depth: Option<u32>,
    /// Bubble plots: bubbles drawn in 3D.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bubble_3d: Option<bool>,
    /// Bubble plots: the bubbles' scale, as a percentage of the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bubble_scale: Option<u32>,
    /// Bubble plots: whether a negative size draws a bubble.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_neg_bubbles: Option<bool>,
    /// Bubble plots: what a size scales.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_represents: Option<SizeRepresents>,
    /// Stock plots: the series that draws each price, by identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock: Option<StockRoles>,
    /// Line and stock plots: a line from each point's highest value to its
    /// lowest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hi_low_lines: Option<bool>,
    /// Line and stock plots: a bar from each point's first value to its
    /// last (up/down bars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_down_bars: Option<bool>,
    /// The up/down bars' gap, as a percentage of a bar's width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_down_gap_width: Option<u32>,
    /// An up bar's fill (its last value above its first), six hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_fill: Option<String>,
    /// A down bar's fill, six hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_fill: Option<String>,
    /// Surface plots, 2D and 3D: drawn as a wireframe, unfilled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireframe: Option<bool>,
    /// Surface plots: the bands the model formats, by index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bands: Option<Vec<SurfaceBand>>,
    /// Of-pie plots: a pie or a bar as the second plot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub of_pie_type: Option<OfPieType>,
    /// Of-pie plots: how the second plot's points are picked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_type: Option<SplitType>,
    /// Of-pie plots: the position, percentage or value a split by
    /// position, percent or value cuts at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_pos: Option<serde_json::Number>,
    /// Of-pie plots: the category points a custom split draws in the second
    /// plot, by identity in the set the plot's first series draws.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_split: Option<Vec<NodeId>>,
    /// Of-pie plots: the second plot's size, 5 to 200 percent of the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_pie_size: Option<u32>,
    /// Of-pie plots: the gap between the two plots, 0 to 500 percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_width: Option<u32>,
    /// Of-pie plots: lines joining the split points to the second plot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ser_lines: Option<bool>,
}

impl ChartPlot {
    /// No settings for the `nth` plot of `family`.
    pub(crate) fn new(family: ChartKind, nth: u32) -> Self {
        Self {
            family,
            nth,
            bar_dir: None,
            grouping: None,
            shape: None,
            gap_depth: None,
            bubble_3d: None,
            bubble_scale: None,
            show_neg_bubbles: None,
            size_represents: None,
            stock: None,
            hi_low_lines: None,
            up_down_bars: None,
            up_down_gap_width: None,
            up_fill: None,
            down_fill: None,
            wireframe: None,
            bands: None,
            of_pie_type: None,
            split_type: None,
            split_pos: None,
            custom_split: None,
            second_pie_size: None,
            gap_width: None,
            ser_lines: None,
        }
    }

    /// Whether it is the settings of the `nth` plot of `kind`.
    pub(crate) fn is(&self, kind: ChartKind, nth: u32) -> bool {
        self.family == kind && self.nth == nth
    }

    /// Whether it sets nothing.
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::new(self.family, self.nth)
    }

    /// These settings as the `nth` plot of `kind` holds them: each setting
    /// `kind` does not hold is dropped (a `clustered` grouping in a line or
    /// area plot too), named in the second list as its chart part names it.
    pub(crate) fn fit(&self, kind: ChartKind, nth: u32) -> (Self, Vec<String>) {
        use ChartKind::{Area, Area3D, Bar, Bar3D, Bubble, Line, Line3D};
        let bar = matches!(kind, Bar | Bar3D);
        let grouped = bar || matches!(kind, Line | Line3D | Area | Area3D);
        let deep = matches!(kind, Bar3D | Line3D | Area3D);
        let bubble = kind == Bubble;
        let mut out = Self {
            family: kind,
            nth,
            bar_dir: self.bar_dir.filter(|_| bar),
            grouping: self
                .grouping
                .filter(|grouping| grouped && (bar || *grouping != PlotGrouping::Clustered)),
            shape: self.shape.filter(|_| kind == Bar3D),
            gap_depth: self.gap_depth.filter(|_| deep),
            bubble_3d: self.bubble_3d.filter(|_| bubble),
            bubble_scale: self.bubble_scale.filter(|_| bubble),
            show_neg_bubbles: self.show_neg_bubbles.filter(|_| bubble),
            size_represents: self.size_represents.filter(|_| bubble),
            ..Self::new(kind, nth)
        };
        let special = special::fit(self, kind, &mut out);
        let dropped = [
            ("barDir", self.bar_dir.is_some(), out.bar_dir.is_some()),
            ("grouping", self.grouping.is_some(), out.grouping.is_some()),
            ("shape", self.shape.is_some(), out.shape.is_some()),
            (
                "gapDepth",
                self.gap_depth.is_some(),
                out.gap_depth.is_some(),
            ),
            (
                "bubble3D",
                self.bubble_3d.is_some(),
                out.bubble_3d.is_some(),
            ),
            (
                "bubbleScale",
                self.bubble_scale.is_some(),
                out.bubble_scale.is_some(),
            ),
            (
                "showNegBubbles",
                self.show_neg_bubbles.is_some(),
                out.show_neg_bubbles.is_some(),
            ),
            (
                "sizeRepresents",
                self.size_represents.is_some(),
                out.size_represents.is_some(),
            ),
        ]
        .into_iter()
        .filter(|&(_, had, kept)| had && !kept)
        .map(|(name, _, _)| name)
        .chain(special)
        .map(str::to_owned)
        .collect();
        (out, dropped)
    }
}

/// A chart's 3D view, as its `c:view3D` holds it: the rotation about the x
/// axis (-90 to 90 degrees) and the y axis (0 to 359), the height and depth
/// as percentages of the width, whether the axes stand at right angles,
/// and the perspective (0 to 240). `None` keeps what the chart holds.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ChartView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rot_x: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rot_y: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r_ang_ax: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<u32>,
}

impl ChartView {
    /// The view a chart that holds none takes when a plot of `kind` makes
    /// it 3D: a pie tilted 30 degrees and unturned, any other family tilted
    /// 15 and turned 20 with right-angle axes (CALLS, D9b fresh 3D view).
    pub(crate) fn fresh(kind: ChartKind) -> Self {
        if kind == ChartKind::Pie3D {
            Self {
                rot_x: Some(30),
                rot_y: Some(0),
                r_ang_ax: Some(false),
                ..Self::default()
            }
        } else {
            Self {
                rot_x: Some(15),
                rot_y: Some(20),
                r_ang_ax: Some(true),
                ..Self::default()
            }
        }
    }
}

/// A series' bubble sizes and 3D bubbles go with its bubble plot: a series
/// drawn in another family holds none.
pub(super) fn drawn(family: ChartKind, series: &mut [ChartSeries]) {
    for line in series {
        if line.family.unwrap_or(family) != ChartKind::Bubble {
            line.bubble_size = None;
            line.bubble_3d = None;
        }
    }
}
