//! A written chart's rewrite over its retained part (OF-510, FIX 3492,
//! FIX 3493): its plots, axes and series, and its own embedded workbook
//! edited in place or rebuilt.

use super::dataset::{Refs, workbook_dataset};
use super::layout::{self, Layout, Resolved, Wanted, first_category, wanted};
use super::{
    READ_BACK, SHEET, Writer, axes, close, format_code, fresh_plot, int, is_axis, kept_plot,
    kept_ser, own_workbook, piece, retyped_axis, same_data, series, workbook,
};
use crate::edit::xml;
use crate::live::LiveError;
use crate::live::conversion::{Conversion, RebuildReason};
use crate::live::convert;
use crate::live::held::{self, C, children};
use crate::live::pptx::{ChartKind, ChartSource, NodeId, NodePayload, WRITTEN_FRAME};
use crate::native_patch::{chart_data, chart_workbook};
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

/// Rewrite a written chart's part to `payload`: its plots as [`plot_plan`]
/// lays them out (a kept plot's series in place with their formatting, a
/// new series formatted after a held one as [`series::fresh`] writes it, a
/// converted or new plot in its family's defaults), its axes as the plots
/// need them (kept, shared, turned between category and value axes when a
/// plot changes between a category and a scatter family, added, or
/// dropped), and every sequence as a reference into the chart's own
/// embedded workbook. That workbook is edited in place where it can be:
/// only the cells the series read are written, and its other sheets,
/// formulas, formats, names and tables keep their bytes
/// ([`workbook::in_place`]). Where it cannot be, it is rebuilt from the
/// live data as before, and `done` names why
/// ([`Conversion::WorkbookRebuilt`]). A chart whose data lived elsewhere (a
/// link, a shared workbook) gets a new embedded workbook, as PowerPoint's
/// Edit Data does; so does a literal chart the payload moves to a
/// workbook, and any other literal chart stays literal. Each live series is
/// written over its own held series, found by its identity through
/// `bound`, the identity each `c:ser` of the part holds in its own order;
/// one resolution of the live series over the held ones drives both the
/// workbook edit and the rewrite ([`layout::resolve`]). The rewrite reads
/// back as the live data, and every cache equals its cells, or it refuses.
/// The parts it changed and the series identities in the order the part
/// now holds them; `done` gets what it did PowerPoint's way.
pub(in crate::live) fn chart(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
    bound: &[NodeId],
    done: &mut Vec<Conversion>,
) -> Result<(Vec<String>, Vec<NodeId>), LiveError> {
    let (part, reason) = match workbook::original(package, chart, payload)? {
        workbook::Original::Absent => return rewrite(package, chart, payload, bound, done, None),
        workbook::Original::Replaced(part, reason) => (part, reason),
        workbook::Original::Own(part) => {
            // The edit runs on a copy: whatever stops it, the rebuild below
            // starts from the package as it was.
            let mut candidate = package.clone();
            let mut kept = Vec::new();
            let reason = match layout::resolve(&candidate, chart, payload, bound, None) {
                Err(_) => RebuildReason::Unreadable,
                Ok(read) => match workbook::in_place(&candidate, &part, &read) {
                    Err(reason) => reason,
                    Ok(edit) => {
                        let planned = Some((edit, read));
                        match rewrite(&mut candidate, chart, payload, bound, &mut kept, planned) {
                            Ok(written) => {
                                *package = candidate;
                                done.extend(kept);
                                return Ok(written);
                            }
                            Err(_) => RebuildReason::ReadBack,
                        }
                    }
                },
            };
            (part, reason)
        }
    };
    let written = rewrite(package, chart, payload, bound, done, None)?;
    done.push(Conversion::WorkbookRebuilt { part, reason });
    Ok(written)
}

/// Rewrite a live-born chart's native seed to `payload`, its workbook
/// rebuilt from the live data: the seed's is the engine's own, holding
/// nothing a deck kept, and holds one series per live series, in the live
/// order. The parts it changed and the series identities in the order the
/// part now holds them.
pub(in crate::live) fn reseed(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
) -> Result<(Vec<String>, Vec<NodeId>), LiveError> {
    let seeded: Vec<NodeId> = match payload {
        NodePayload::Chart { series, .. } => series.iter().filter_map(|line| line.id).collect(),
        _ => Vec::new(),
    };
    rewrite(package, chart, payload, &seeded, &mut Vec::new(), None)
}

/// [`chart`]'s rewrite: into the chart's own workbook as `in_place` edits
/// it, over the resolution that edit read, or, without an edit, into one
/// rebuilt from the live data.
fn rewrite(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
    bound: &[NodeId],
    done: &mut Vec<Conversion>,
    in_place: Option<(workbook::InPlace, Resolved)>,
) -> Result<(Vec<String>, Vec<NodeId>), LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        source,
    } = payload
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let mut changed = vec![chart.to_owned()];
    let (edit, read, book) = match in_place {
        Some((edit, read)) => {
            let book = Some(edit.part.clone());
            (Some(edit), read, book)
        }
        None => {
            let (_, first) = xml::read(package, chart)?;
            let wanted = wanted(&first, *family, categories, series);
            let book = match own_workbook(package, chart, &first)? {
                Some(book) => Some(book),
                None if *source == ChartSource::Literal => None,
                None => {
                    let dataset = workbook_dataset(categories, &wanted);
                    let workbook = chart_workbook(&dataset, SHEET, package.limits())?;
                    let (book, embedded) = convert::embed_workbook(package, chart, workbook)?;
                    done.extend(embedded);
                    Some(book)
                }
            };
            let read = layout::resolve(package, chart, payload, bound, Some(wanted))?;
            (None, read, book)
        }
    };
    let dataset = workbook_dataset(categories, &read.wanted);
    let Resolved {
        bytes,
        tree,
        wanted:
            Wanted {
                numeric_cats,
                category_cells,
                data,
                ..
            },
        layout:
            Layout {
                area,
                plots,
                targets,
                assigned,
                seats,
            },
    } = read;
    for target in &targets {
        match target.held {
            Some(at) if plots[at].0 != target.kind => done.push(Conversion::ChartTypeChanged {
                from: plots[at].0,
                to: target.kind,
            }),
            Some(_) => {}
            None => done.push(Conversion::PlotAdded {
                family: target.kind,
            }),
        }
    }
    for (at, &(kind, _)) in plots.iter().enumerate() {
        if !targets.iter().any(|target| target.held == Some(at)) {
            done.push(Conversion::PlotDropped { family: kind });
        }
    }
    let first_cat = first_category(&tree);
    let c = match xml::prefix(&tree.nodes[area]) {
        "" => String::new(),
        prefix => format!("{prefix}:"),
    };
    let writer = Writer { c };
    let mut next_idx = tree
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is(C, "ser"))
        .filter_map(|(at, _)| int(&tree, at, "idx").max(int(&tree, at, "order")))
        .max()
        .map_or(0, |top| top.saturating_add(1));
    // The axes each plot plots on: a held plot's own, another plot's of the
    // same kind, or a new pair, each id above every id the chart holds. A
    // held x axis turns between a category and a value axis with its plot.
    let held_axes: Vec<(u32, usize)> = tree.nodes[area]
        .children
        .iter()
        .copied()
        .filter(|&at| is_axis(&tree.nodes[at]))
        .filter_map(|at| Some((int(&tree, at, "axId")?, at)))
        .collect();
    let mut fresh = tree
        .nodes
        .iter()
        .filter(|node| node.is(C, "axId"))
        .filter_map(|node| node.attr("val")?.trim().parse::<u32>().ok())
        .max()
        .map_or(1, |top| top.saturating_add(1));
    let mut value_x: BTreeMap<u32, bool> = held_axes
        .iter()
        .map(|&(id, at)| (id, tree.nodes[at].name == "valAx"))
        .collect();
    let mut retyped: BTreeMap<u32, bool> = BTreeMap::new();
    let mut new_axes = String::new();
    let mut ids_of: Vec<Vec<u32>> = Vec::with_capacity(targets.len());
    for target in &targets {
        let wants_value = target.kind == ChartKind::Scatter;
        let kept: Vec<u32> = target
            .held
            .filter(|&at| plots[at].0.has_axes())
            .map(|at| {
                children(&tree, plots[at].1, C, "axId")
                    .filter_map(|id| tree.nodes[id].attr("val")?.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let shared = ids_of
            .iter()
            .find(|ids| {
                ids.len() >= 2 && value_x.get(&ids[0]).copied().unwrap_or(false) == wants_value
            })
            .cloned();
        let ids = if !target.kind.has_axes() {
            Vec::new()
        } else if let Some(&x) = kept.first() {
            if value_x.get(&x).copied().unwrap_or(false) != wants_value {
                retyped.insert(x, wants_value);
                value_x.insert(x, wants_value);
            }
            kept
        } else if let Some(ids) = shared {
            ids
        } else {
            let secondary = ids_of.iter().any(|ids| !ids.is_empty());
            new_axes.push_str(&axes(&writer, fresh, wants_value, secondary));
            value_x.insert(fresh, wants_value);
            let ids = vec![fresh, fresh.saturating_add(1)];
            fresh = fresh.saturating_add(2);
            ids
        };
        ids_of.push(ids);
    }
    // The display order follows the live order. Each survivor keeps its own
    // `c:order` while the survivors keep the order the part holds them in
    // (no series moved) and every new series follows them; else each series
    // takes its place in the live order. A survivor's `c:idx` is its own.
    let keep_order = {
        let (mut last, mut born) = (None, false);
        seats.iter().all(|seat| match seat.held {
            None => {
                born = true;
                true
            }
            Some(ser) => {
                let kept = !born && Some(ser) > last;
                last = Some(ser);
                kept
            }
        })
    };
    let mut plot_xml: Vec<Vec<u8>> = Vec::with_capacity(targets.len());
    let mut emitted: Vec<usize> = Vec::with_capacity(seats.len());
    for (at_target, target) in targets.iter().enumerate() {
        let kind = target.kind;
        let kept = target.held.filter(|&at| plots[at].0 == kind);
        let mut sers = Vec::new();
        for &index in &assigned[at_target] {
            emitted.push(index);
            let seat = seats[index];
            let place = u32::try_from(index).unwrap_or(u32::MAX);
            let (idx, order) = match seat.held {
                Some(ser) => (
                    int(&tree, ser, "idx").unwrap_or(next_idx),
                    if keep_order {
                        int(&tree, ser, "order").unwrap_or(next_idx)
                    } else {
                        place
                    },
                ),
                None => {
                    let minted = next_idx;
                    next_idx = next_idx.saturating_add(1);
                    (minted, if keep_order { minted } else { place })
                }
            };
            let line = &data[index];
            let rebuilt;
            let refs = match &edit {
                Some(edit) => &edit.refs[index],
                None => {
                    rebuilt = if book.is_some() {
                        Refs::rebuilt(line, categories.len())
                    } else {
                        Refs::default()
                    };
                    &rebuilt
                }
            };
            let scatter = kind == ChartKind::Scatter;
            let (cat_name, val_name) = if scatter {
                ("xVal", "yVal")
            } else {
                ("cat", "val")
            };
            let cat_slot = seat
                .template
                .and_then(|ser| xml::child(&tree, ser, C, cat_name));
            let val_slot = seat
                .template
                .and_then(|ser| xml::child(&tree, ser, C, val_name));
            let cat_xml = match (&line.x, scatter) {
                (Some(x), true) => writer.slot(
                    cat_name,
                    true,
                    refs.first.as_deref(),
                    x,
                    &format_code(&bytes, &tree, cat_slot),
                ),
                (None, false) if !categories.is_empty() => writer.slot(
                    cat_name,
                    numeric_cats,
                    refs.first.as_deref(),
                    &category_cells,
                    &format_code(&bytes, &tree, cat_slot.or(first_cat)),
                ),
                _ => String::new(),
            };
            let val_xml = writer.slot(
                val_name,
                true,
                refs.values.as_deref(),
                &line.values,
                &format_code(&bytes, &tree, val_slot),
            );
            let tx = writer.tx(&line.name, refs.name.as_deref());
            let count = line.values.len();
            // A survivor keeps its own series' bytes in the plot that held
            // it; drawn in another plot, it is formatted after its own.
            let own_plot = seat.held.and_then(|ser| tree.nodes[ser].parent);
            let in_kept = kept.is_some_and(|at| own_plot == Some(plots[at].1));
            sers.extend(match seat.held.filter(|_| in_kept) {
                Some(ser) => kept_ser(
                    &bytes,
                    &tree,
                    ser,
                    (idx, order),
                    &writer,
                    [&tx, &cat_xml, &val_xml],
                    count,
                )?,
                None => series::fresh(
                    &bytes,
                    &tree,
                    seat.template,
                    kind,
                    &writer,
                    (idx, order),
                    [&tx, &cat_xml, &val_xml],
                ),
            });
        }
        plot_xml.push(match kept {
            Some(at) => kept_plot(&bytes, &tree, plots[at].1, &sers),
            None => fresh_plot(kind, &writer, &sers, &ids_of[at_target]),
        });
    }
    // The axes: each held axis a plot still plots on (turned where its plot
    // changed kind), then the new ones.
    let referenced: BTreeSet<u32> = ids_of.iter().flatten().copied().collect();
    let mut axes_xml = Vec::new();
    for &(id, at) in &held_axes {
        if !referenced.contains(&id) {
            continue;
        }
        match retyped.get(&id) {
            Some(&value) => axes_xml.extend(retyped_axis(&bytes, &tree, at, value, &writer)),
            None => axes_xml.extend_from_slice(piece(&bytes, &tree, at)),
        }
    }
    axes_xml.extend(new_axes.into_bytes());
    // The plot area: the plots where the held ones stood, then the axes
    // before anything that follows them.
    let held_at: BTreeSet<usize> = plots.iter().map(|&(_, at)| at).collect();
    let mut out = xml::open_tag(&bytes, &tree.nodes[area]);
    let mut plots_xml = Some(plot_xml.concat());
    let mut axes_xml = Some(axes_xml);
    for &child in &tree.nodes[area].children {
        let node = &tree.nodes[child];
        if held_at.contains(&child) {
            if let Some(xml) = plots_xml.take() {
                out.extend(xml);
            }
            continue;
        }
        let after =
            node.namespace == C && matches!(node.name.as_str(), "dTable" | "spPr" | "extLst");
        if is_axis(node) || (after && plots_xml.is_none()) {
            if let Some(xml) = axes_xml.take() {
                out.extend(xml);
            }
            if is_axis(node) {
                continue;
            }
        }
        out.extend_from_slice(piece(&bytes, &tree, child));
    }
    if let Some(xml) = axes_xml.take() {
        out.extend(xml);
    }
    out.extend(close(&tree.nodes[area]));
    let next = xml::splice(&bytes, vec![(tree.nodes[area].span.clone(), out)])?;
    package.replace_xml_part(chart, next)?;
    if let Some(book) = &book {
        let (workbook, notes) = match edit {
            Some(edit) => (edit.bytes, edit.notes),
            None => (
                Some(chart_workbook(&dataset, SHEET, package.limits())?),
                Vec::new(),
            ),
        };
        if let Some(workbook) = workbook {
            package.replace_nested_package(book, workbook)?;
            changed.push(book.clone());
        }
        let read = chart_data(package, chart)?;
        let agree = read
            .series
            .iter()
            .flat_map(|line| [&line.name, &line.categories, &line.values])
            .flatten()
            .all(|sequence| {
                sequence
                    .cache
                    .iter()
                    .map(held::label)
                    .eq(sequence.workbook.iter().map(held::label))
            });
        if !agree {
            return Err(LiveError::Invalid(READ_BACK));
        }
        done.extend(notes);
    }
    // The part reads back as the live series in the order it holds them.
    let written = NodePayload::Chart {
        family: *family,
        categories: categories.clone(),
        series: emitted.iter().map(|&index| series[index].clone()).collect(),
        source: *source,
    };
    let read = held::chart(package, chart).ok_or(LiveError::Invalid(READ_BACK))?;
    if !same_data(&read, &written) {
        return Err(LiveError::Invalid(READ_BACK));
    }
    let order = emitted
        .iter()
        .filter_map(|&index| series[index].id)
        .collect();
    Ok((changed, order))
}
