//! The conflicts of a chart both sides of a fork wrote (`conflicts`), and
//! where each side moved a series among the chart's plots.

use super::categories::{Sides, competing, series_conflicts, set_conflicts, values_compete};
use super::{ChartKind, ChartPlot, ChartSeries, SeriesField};
use crate::live::pptx::{Conflict, DeckNode, NodeId, NodePayload};
use std::collections::BTreeSet;

/// The plot of its family that draws one series: its family and its
/// ordinal among the family's plots (`None` the only one).
fn plot_key(family: ChartKind, line: &ChartSeries) -> (ChartKind, u32) {
    (line.family.unwrap_or(family), line.plot.unwrap_or(0))
}

/// Where one side of a fork moved the series `id` to, among its base
/// plots (FIX 12255): the base ordinals of the plot it drew it in, or an
/// empty list for a plot of its own; `None` where it stayed in its base
/// plot. A move-aware compare, never a plain field one: settlement
/// renumbers ordinals when a plot goes, so the series counts as moved only
/// where it left its base plot-mates: beside series of another base plot,
/// or alone while a mate it left behind stayed put. A series with its
/// mates, one whose mates are gone, and one whose family changed (placed
/// by settlement, not moved) never count as moved. A co-occupant that
/// itself moved to the destination names its own move, never this one's.
fn plot_moved(
    base_family: ChartKind,
    base_series: &[ChartSeries],
    side_family: ChartKind,
    side_series: &[ChartSeries],
    id: NodeId,
) -> Option<Vec<u32>> {
    let base = base_series.iter().find(|line| line.id == Some(id))?;
    let side = side_series.iter().find(|line| line.id == Some(id))?;
    let (family, ordinal) = plot_key(base_family, base);
    if side.family.unwrap_or(side_family) != family {
        return None;
    }
    let known: BTreeSet<NodeId> = base_series.iter().filter_map(|line| line.id).collect();
    let base_key = |other: NodeId| -> Option<(ChartKind, u32)> {
        base_series
            .iter()
            .find(|was| was.id == Some(other))
            .map(|was| plot_key(base_family, was))
    };
    let (_, at) = plot_key(side_family, side);
    // No raw-ordinal early return here (review-4320 P1): settlement
    // renumbers ordinals when a plot goes, so `at == ordinal` does not
    // prove the series stayed in its base plot. The mate-aware compare
    // below decides instead: co-occupants from another base plot mark a
    // different logical destination, while pure settlement renumbering
    // (mates beside it, mates gone, family changed) stays silent.
    // Its side plot's base series, drawn in its family there as in the
    // base: a new series never moves it, and a series that changed family
    // is judged by that field instead. A co-occupant whose base plot holds
    // a stronger claim elsewhere moved here on its own: it names its own
    // move, never this series' destination; one this destination retained,
    // beside its mates, or with none surviving elsewhere, still anchors it.
    let mut targets: Vec<u32> = Vec::new();
    for line in side_series {
        let Some(other) = line.id else {
            continue;
        };
        if other == id || !known.contains(&other) {
            continue;
        }
        if plot_key(side_family, line) != (family, at) {
            continue;
        }
        let Some((kind, nth)) = base_key(other) else {
            continue;
        };
        if kind != family {
            continue;
        }
        if nth != ordinal {
            // A co-occupant that left surviving base-plot mates behind moved
            // here on its own: it names its own move, never this series'
            // destination — unless this destination still holds its base
            // plot's strongest claim (review-4320 P1): the mates'
            // departures do not move an occupant the destination retained.
            // An occupied unchanged ordinal keeps the plot's claim even
            // when more natives moved elsewhere. Among changed ordinals,
            // the surviving native count decides. A foreign-only plot at
            // the old ordinal carries no claim.
            let plot_claim = |place: u32| -> (bool, usize) {
                let count = side_series
                    .iter()
                    .filter(|line| {
                        line.id
                            .is_some_and(|mate| base_key(mate) == Some((family, nth)))
                            && plot_key(side_family, line) == (family, place)
                    })
                    .count();
                (count != 0 && place == nth, count)
            };
            let here = plot_claim(at);
            let moved = side_series.iter().any(|line| {
                let (_, place) = plot_key(side_family, line);
                place != at && plot_claim(place) > here
            });
            if moved {
                continue;
            }
            targets.push(nth);
        }
    }
    // At least one base-plot mate exists, and every surviving one joined
    // the destination: a group move, not an own move. One surviving mate
    // left behind still makes it a move; no mate at all never suppresses it.
    let mut mates = base_series
        .iter()
        .filter_map(|line| line.id)
        .filter(|&other| other != id && base_key(other) == Some((family, ordinal)))
        .peekable();
    let joined = mates.peek().is_some()
        && mates.all(|other| {
            side_series
                .iter()
                .any(|line| line.id == Some(other) && plot_key(side_family, line) == (family, at))
        });
    if !targets.is_empty() {
        // Beside series of another base plot: moved, unless every surviving
        // base-plot mate joined it there too.
        if joined {
            return None;
        }
        targets.sort_unstable();
        targets.dedup();
        return Some(targets);
    }
    // Its surviving mates drawn elsewhere: moved to a plot of its own only
    // where it sits alone and a mate it left behind stayed put.
    let left: Vec<NodeId> = base_series
        .iter()
        .filter_map(|line| line.id)
        .filter(|&other| {
            other != id
                && base_key(other) == Some((family, ordinal))
                && side_series.iter().any(|line| line.id == Some(other))
                && !side_series.iter().any(|line| {
                    line.id == Some(other) && plot_key(side_family, line) == (family, at)
                })
        })
        .collect();
    if left.is_empty() || joined {
        return None;
    }
    let last = side_series
        .iter()
        .filter(|line| line.family.unwrap_or(side_family) == family)
        .map(|line| line.plot.unwrap_or(0))
        .max();
    for other in left {
        let Some(mate) = side_series.iter().find(|line| line.id == Some(other)) else {
            continue;
        };
        let (_, place) = plot_key(side_family, mate);
        let mut company = false;
        let mut foreign = false;
        for line in side_series {
            let Some(next) = line.id else {
                continue;
            };
            if next == other || !known.contains(&next) {
                continue;
            }
            if plot_key(side_family, line) != (family, place) {
                continue;
            }
            let Some((kind, nth)) = base_key(next) else {
                continue;
            };
            if kind != family {
                continue;
            }
            company = true;
            foreign |= nth != ordinal;
        }
        // A mate drawn with no series of another base plot stayed put; one
        // alone in the family's last plot moved to a plot of its own.
        if !foreign && (company || Some(place) != last) {
            return Some(Vec::new());
        }
    }
    None
}

/// Concurrently-created plots with the same series are the same destination
/// for a move. Their independently-reserved identities stay fresh; neither
/// destination may be a plot retained from the common base.
fn same_new_plot_destination(
    base: &[ChartSeries],
    head: &[ChartSeries],
    head_plot: NodeId,
    proposal: &[ChartSeries],
    proposal_plot: NodeId,
) -> bool {
    if base.iter().any(|line| {
        line.plot_id
            .is_some_and(|id| id == head_plot || id == proposal_plot)
    }) {
        return false;
    }
    let members = |series: &[ChartSeries], plot| -> BTreeSet<NodeId> {
        series
            .iter()
            .filter(|line| line.plot_id == Some(plot))
            .filter_map(|line| line.id)
            .collect()
    };
    let head = members(head, head_plot);
    !head.is_empty() && head == members(proposal, proposal_plot)
}

/// Whether two move destinations name the same plot (review-4320 P1):
/// two non-empty destinations share a base-plot ordinal, while a solo
/// `[]` only ever equals `[]`.
fn same_plot_destination(head: &[u32], proposal: &[u32]) -> bool {
    if head.is_empty() || proposal.is_empty() {
        return head == proposal;
    }
    head.iter().any(|nth| proposal.contains(nth))
}

/// The conflicts of a chart both sides of a fork wrote, when the base, the
/// head and the proposal all hold a chart: one series' name, values, family,
/// x values or draw of categories both sides wrote differently, one series
/// both sides moved to different plots of its family (FIX 12255), one series
/// both sides moved to different places (among the series all three hold),
/// or one series one side deleted and the other wrote
/// ([`Conflict::SeriesVsSeries`]); one category point of the chart's set or
/// of a series' own both sides relabelled, moved or one deleted and the
/// other wrote ([`Conflict::CategoryVsCategory`]); and the chart's family,
/// data source or category depth both sides wrote differently
/// ([`Conflict::PayloadVsPayload`]). A category series' values compete
/// point by point, through the points' identities. Series and points
/// inserted, deleted, moved or written by one side only, and different
/// fields of one series, join without conflict. `None` when one of them
/// holds no chart.
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
            plots: base_plots,
            view: base_view,
        }),
        Some(NodePayload::Chart {
            family: head_family,
            categories: head_categories,
            series: head_series,
            source: head_source,
            plots: head_plots,
            view: head_view,
        }),
        Some(NodePayload::Chart {
            family: proposal_family,
            categories: proposal_categories,
            series: proposal_series,
            source: proposal_source,
            plots: proposal_plots,
            view: proposal_view,
        }),
    ) = (&base.payload, &head.payload, &proposal.payload)
    else {
        return None;
    };
    if base.preset != head.preset || base.preset != proposal.preset {
        return None;
    }
    let mut out = Vec::new();
    // One plot's settings compete as a whole, plot by plot.
    let plot = |plots: &[ChartPlot], at: &ChartPlot| -> Option<ChartPlot> {
        plots
            .iter()
            .find(|held| held.is(at.family, at.nth))
            .cloned()
    };
    let plots_compete = base_plots
        .iter()
        .chain(head_plots)
        .chain(proposal_plots)
        .any(|at| {
            competing(
                &plot(base_plots, at),
                &plot(head_plots, at),
                &plot(proposal_plots, at),
            )
        });
    if competing(base_family, head_family, proposal_family)
        || competing(base_source, head_source, proposal_source)
        || competing(base_view, head_view, proposal_view)
        || plots_compete
    {
        out.push(Conflict::PayloadVsPayload { node });
    }
    set_conflicts(
        node,
        None,
        [base_categories, head_categories, proposal_categories],
        Conflict::PayloadVsPayload { node },
        &mut out,
    );
    out.dedup();
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
                let sides = Sides {
                    family: [*base_family, *head_family, *proposal_family],
                    chart: [base_categories, head_categories, proposal_categories],
                    line: [was, &head, &proposal],
                };
                for (field, both) in [
                    (
                        SeriesField::Name,
                        competing(&was.name, &head.name, &proposal.name),
                    ),
                    (SeriesField::Values, values_compete(&sides)),
                    (
                        SeriesField::Family,
                        competing(&was.family, &head.family, &proposal.family),
                    ),
                    (
                        SeriesField::X,
                        competing(
                            &(&was.x, &was.x_labels),
                            &(&head.x, &head.x_labels),
                            &(&proposal.x, &proposal.x_labels),
                        ),
                    ),
                    (
                        SeriesField::BubbleSize,
                        competing(&was.bubble_size, &head.bubble_size, &proposal.bubble_size),
                    ),
                    (
                        SeriesField::Bubble3D,
                        competing(&was.bubble_3d, &head.bubble_3d, &proposal.bubble_3d),
                    ),
                ] {
                    if both {
                        out.push(series(field));
                    }
                }
                series_conflicts(node, id, &sides, &mut out);
                if competing(
                    &before(base_series, id),
                    &before(head_series, id),
                    &before(proposal_series, id),
                ) {
                    out.push(series(SeriesField::Order));
                }
                // Logical identities survive ordinal compaction (FIX 12770).
                // Missing evidence keeps the existing mate-aware comparison.
                let plots_compete = match (was.plot_id, head.plot_id, proposal.plot_id) {
                    (Some(base), Some(head_id), Some(proposal_id))
                        if head.family.unwrap_or(*head_family)
                            == was.family.unwrap_or(*base_family)
                            && proposal.family.unwrap_or(*proposal_family)
                                == was.family.unwrap_or(*base_family) =>
                    {
                        competing(&base, &head_id, &proposal_id)
                            && !same_new_plot_destination(
                                base_series,
                                head_series,
                                head_id,
                                proposal_series,
                                proposal_id,
                            )
                    }
                    _ => {
                        let head_plot =
                            plot_moved(*base_family, base_series, *head_family, head_series, id);
                        let proposal_plot = plot_moved(
                            *base_family,
                            base_series,
                            *proposal_family,
                            proposal_series,
                            id,
                        );
                        matches!((head_plot, proposal_plot), (Some(head), Some(proposal))
                            if !same_plot_destination(&head, &proposal))
                    }
                };
                if plots_compete {
                    out.push(series(SeriesField::Plot));
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
