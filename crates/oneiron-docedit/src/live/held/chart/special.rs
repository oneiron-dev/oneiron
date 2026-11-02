//! A chart part's stock, surface and of-pie settings as the live model
//! holds them (OF-510, FIX 3493 D9c): each plot's high-low lines, up/down
//! bars, wireframe, band fills, second plot and split, read from its bytes;
//! and the evidence that names a stock plot's prices and an of-pie plot's
//! custom split by identity: which `c:ser` each plot holds and which point
//! indices its split names. A read names no identity: [`named`] gives the
//! evidence its identities through a binding, once at import and again for
//! every comparison of a part with the model.

use super::{C, children, plots};
use crate::edit::xml::{self, A};
use crate::live::pptx::{
    ChartKind, ChartPlot, NodeId, OfPieType, SeriesBinding, SplitType, StockRoles, SurfaceBand,
    lines_and_bars, surface,
};
use crate::native_patch::stock_placeholder;
use crate::ooxml::XmlTree;
use std::collections::BTreeSet;

/// The `val` of `at`'s child `name`.
fn val<'t>(tree: &'t XmlTree, at: usize, name: &str) -> Option<&'t str> {
    tree.nodes[xml::child(tree, at, C, name)?].attr("val")
}

fn number<T: std::str::FromStr>(tree: &XmlTree, at: usize, name: &str) -> Option<T> {
    val(tree, at, name)?
        .trim()
        .trim_end_matches('%')
        .parse()
        .ok()
}

/// The solid fill a `c:spPr` under `at` holds, as six upper-case hex
/// digits; none for any other fill.
pub(crate) fn fill(tree: &XmlTree, at: usize) -> Option<String> {
    let sp = xml::child(tree, at, C, "spPr")?;
    let solid = xml::child(tree, sp, A, "solidFill")?;
    let rgb = tree.nodes[xml::child(tree, solid, A, "srgbClr")?].attr("val")?;
    let rgb = rgb.trim();
    (rgb.len() == 6 && rgb.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| rgb.to_ascii_uppercase())
}

/// A gap a part holds, when the model can hold it (0 to 500 percent): one
/// outside is no setting, its bytes kept.
fn gap(tree: &XmlTree, at: usize) -> Option<u32> {
    number::<u32>(tree, at, "gapWidth").filter(|gap| *gap <= 500)
}

/// The special settings the `kind` plot at `at` holds, read into `plot`:
/// only those `kind` holds ([`ChartPlot::fit`] drops the rest).
pub(super) fn read(tree: &XmlTree, kind: ChartKind, at: usize, plot: &mut ChartPlot) {
    let has = |name: &str| xml::child(tree, at, C, name).is_some();
    if lines_and_bars(kind) {
        // A stock plot says whether it draws them; a line plot only when it
        // does.
        let stock = kind == ChartKind::Stock;
        plot.hi_low_lines = (stock || has("hiLowLines")).then(|| has("hiLowLines"));
        plot.up_down_bars = (stock || has("upDownBars")).then(|| has("upDownBars"));
        if let Some(bars) = xml::child(tree, at, C, "upDownBars") {
            plot.up_down_gap_width = gap(tree, bars);
            plot.up_fill = xml::child(tree, bars, C, "upBars").and_then(|up| fill(tree, up));
            plot.down_fill =
                xml::child(tree, bars, C, "downBars").and_then(|down| fill(tree, down));
        }
    }
    if surface(kind) {
        plot.wireframe = super::flag(tree, at, "wireframe");
        let bands: Vec<SurfaceBand> = xml::child(tree, at, C, "bandFmts")
            .map(|bands| {
                children(tree, bands, C, "bandFmt")
                    .filter_map(|band| {
                        Some(SurfaceBand {
                            index: number(tree, band, "idx")?,
                            fill: Some(fill(tree, band)?),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        plot.bands = (!bands.is_empty()).then_some(bands);
    }
    if kind == ChartKind::OfPie {
        plot.of_pie_type = val(tree, at, "ofPieType").and_then(OfPieType::parse);
        plot.split_type = val(tree, at, "splitType").and_then(SplitType::parse);
        plot.split_pos = number::<f64>(tree, at, "splitPos").and_then(serde_json::Number::from_f64);
        plot.second_pie_size =
            number(tree, at, "secondPieSize").filter(|size| (5..=200).contains(size));
        plot.gap_width = gap(tree, at);
        plot.ser_lines = Some(has("serLines"));
    }
}

/// The custom split's point indices an of-pie plot element holds.
pub(crate) fn split(tree: &XmlTree, at: usize) -> Vec<usize> {
    xml::child(tree, at, C, "custSplit").map_or_else(Vec::new, |split| {
        children(tree, split, C, "secondPiePt")
            .filter_map(|pt| tree.nodes[pt].attr("val")?.trim().parse().ok())
            .collect()
    })
}

/// One stock or of-pie plot as its part holds it, without identities: the
/// nth plot of its family, the places of its `c:ser` among every series of
/// the part (its plots in document order), a stock plot's placeholder
/// (FIX 9374) holding its own place in the plot's price order but none
/// among the series (`None`), and an of-pie plot's custom split point
/// indices.
pub(crate) struct Evidence {
    kind: ChartKind,
    nth: u32,
    series: Vec<Option<usize>>,
    split: Option<Vec<usize>>,
}

/// The stock and of-pie plots a chart part holds.
pub(crate) fn evidence(tree: &XmlTree) -> Vec<Evidence> {
    let Some((_, plots)) = plots(tree) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut place = 0;
    for (index, &(kind, at)) in plots.iter().enumerate() {
        let mut series = Vec::new();
        for ser in children(tree, at, C, "ser") {
            if stock_placeholder(tree, ser) {
                series.push(None);
            } else {
                series.push(Some(place));
                place += 1;
            }
        }
        if matches!(kind, ChartKind::Stock | ChartKind::OfPie) {
            let nth = plots[..index]
                .iter()
                .filter(|(other, _)| *other == kind)
                .count();
            out.push(Evidence {
                kind,
                nth: u32::try_from(nth).unwrap_or(u32::MAX),
                series,
                split: (kind == ChartKind::OfPie && xml::child(tree, at, C, "custSplit").is_some())
                    .then(|| split(tree, at)),
            });
        }
    }
    out
}

/// The stock prices and custom splits `evidence` names through `bound`
/// (each series' identity and category identities, in part order): a
/// stock plot's `c:ser` take its prices in their order (three high, low
/// and close; four or more open first, a fifth and later one none), a
/// placeholder's price left empty; and an of-pie plot's split points are
/// the points at those indices of each set its series draw (FIX 9375: one
/// native split names the same indices in every series' set). Each as the
/// nth plot of its family, holding only these settings, with the category
/// identities its series draw, the first series' first.
pub(crate) fn named(evidence: &[Evidence], bound: &SeriesBinding) -> Vec<(ChartPlot, Vec<NodeId>)> {
    evidence
        .iter()
        .map(|plot| {
            let sets: Vec<&[NodeId]> = plot
                .series
                .iter()
                .flatten()
                .filter_map(|&at| bound.categories.get(at).map(Vec::as_slice))
                .collect();
            let mut drawn = BTreeSet::new();
            let set: Vec<NodeId> = sets
                .iter()
                .copied()
                .flat_map(|set| set.iter().copied())
                .filter(|id| drawn.insert(*id))
                .collect();
            let mut out = ChartPlot::new(plot.kind, plot.nth);
            if plot.kind == ChartKind::Stock {
                let ids: Vec<Option<NodeId>> = plot
                    .series
                    .iter()
                    .map(|at| at.and_then(|at| bound.series.get(at).copied()))
                    .collect();
                let mut roles = StockRoles::empty(StockRoles::order_for(ids.len()));
                for (slot, id) in roles.slots_mut().into_iter().zip(ids) {
                    *slot = id;
                }
                out.stock = Some(roles);
            }
            if let Some(split) = &plot.split {
                let mut seen = BTreeSet::new();
                out.custom_split = Some(
                    sets.iter()
                        .copied()
                        .flat_map(|set| split.iter().filter_map(move |&at| set.get(at).copied()))
                        .filter(|id| seen.insert(*id))
                        .collect(),
                );
            }
            (out, set)
        })
        .collect()
}

/// Whether the chart part `tree` holds the stock prices and custom splits
/// `wanted` sets, through `bound`: each stock plot's priced series in its
/// price order, each at its own price's place (a price the part's plot
/// does not draw is one `wanted` leaves empty, its placeholder holding its
/// place, FIX 9374), and each of-pie plot's split the same points of the
/// sets its series draw.
pub(crate) fn same_named(tree: &XmlTree, bound: &SeriesBinding, wanted: &[ChartPlot]) -> bool {
    let held = named(&evidence(tree), bound);
    wanted.iter().all(|plot| {
        let found = held.iter().find(|(have, _)| have.is(plot.family, plot.nth));
        let have = found.map(|(have, _)| have);
        let set = found.map_or(&[][..], |(_, set)| set.as_slice());
        let roles = plot.stock.as_ref().is_none_or(|roles| {
            let drawn = roles.drawn();
            let held_roles = have.and_then(|have| have.stock.as_ref());
            let have: Vec<NodeId> = held_roles
                .map_or_else(Vec::new, StockRoles::drawn)
                .into_iter()
                .filter(|id| drawn.contains(id))
                .collect();
            have == drawn
                && drawn.iter().all(|id| {
                    held_roles.and_then(|held| held.rank(Some(*id))) == roles.rank(Some(*id))
                })
        });
        let split = plot.custom_split.as_ref().is_none_or(|split| {
            let want: BTreeSet<NodeId> = split
                .iter()
                .copied()
                .filter(|id| set.contains(id))
                .collect();
            let have: BTreeSet<NodeId> = have
                .and_then(|have| have.custom_split.as_ref())
                .into_iter()
                .flatten()
                .copied()
                .collect();
            have == want
        });
        roles && split
    })
}
