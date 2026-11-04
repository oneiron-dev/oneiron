//! A written chart's rewrite over its retained part (OF-510, FIX 3492,
//! FIX 3493): its plots, axes and series, and its own embedded workbook
//! edited in place or rebuilt.

use super::axes::{PlotAxes, mid_cat_axis, plot_axes};
use super::dataset::{self, Refs, workbook_dataset};
use super::families::{self, bit};
use super::layout::{self, Layout, Resolved, Wanted, first_category, wanted};
use super::retained::{Slots, retained};
use super::special::{self, Context};
use super::{
    Points, READ_BACK, SHEET, Writer, close, format_code, fresh_plot, int, is_axis, kept_plot,
    own_workbook, piece, remap, retyped_axis, same_data, same_settings, series, workbook,
};
use crate::edit::xml;
use crate::live::LiveError;
use crate::live::conversion::{Conversion, RebuildReason};
use crate::live::convert;
use crate::live::held::{self, C};
use crate::live::pptx::{
    ChartKind, ChartSeries, ChartSource, NodeId, NodePayload, SeriesBinding, WRITTEN_FRAME,
    draws_categories, effective_categories,
};
use crate::native_patch::{chart_data, chart_workbook};
use crate::retained_opc::Package;
use std::collections::BTreeSet;

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
    bound: &SeriesBinding,
    done: &mut Vec<Conversion>,
) -> Result<(Vec<String>, Vec<NodeId>), LiveError> {
    let (part, reason) = match workbook::original(package, chart, payload)? {
        workbook::Original::Absent => {
            return rewrite(package, chart, payload, bound, done, Mode::Rebuild(None));
        }
        workbook::Original::Replaced(part, reason) => (part, reason),
        workbook::Original::Own(part) => {
            // The edit runs on a copy: whatever stops it, the rebuild below
            // starts from the package as it was.
            let mut candidate = package.clone();
            let mut kept = Vec::new();
            let reason = match layout::resolve(&candidate, chart, payload, &bound.series, None) {
                Err(_) => RebuildReason::Unreadable,
                Ok(read) => match workbook::in_place(&candidate, &part, &read) {
                    Err(reason) => reason,
                    Ok(edit) => {
                        let planned = Mode::Edit(edit, read);
                        match rewrite(&mut candidate, chart, payload, bound, &mut kept, planned) {
                            Ok(written) => {
                                *package = candidate;
                                done.extend(kept);
                                return Ok(written);
                            }
                            // What the host cannot hold is no reason to
                            // rebuild (FIX 8589).
                            Err(error @ LiveError::MemoryFloor { .. }) => return Err(error),
                            Err(_) => RebuildReason::ReadBack,
                        }
                    }
                },
            };
            (part, reason)
        }
    };
    rewrite(
        package,
        chart,
        payload,
        bound,
        done,
        Mode::Rebuild(Some((part, reason))),
    )
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
    let seeded = SeriesBinding {
        series: match payload {
            NodePayload::Chart { series, .. } => series.iter().filter_map(|line| line.id).collect(),
            _ => Vec::new(),
        },
        categories: Vec::new(),
    };
    rewrite(
        package,
        chart,
        payload,
        &seeded,
        &mut Vec::new(),
        Mode::Seed,
    )
}

/// How a rewrite writes the chart's workbook.
enum Mode {
    /// Edited in place as [`workbook::in_place`] planned it, over the
    /// resolution that plan read.
    Edit(workbook::InPlace, Resolved),
    /// Rebuilt from the live data: the chart's own workbook keeps its
    /// sheets, the data on a new one beside them (FIX 6714) or on its own
    /// data sheet rewritten (FIX 9169); one the chart does not own is
    /// replaced. The workbook not edited in place, and why, for the
    /// receipt.
    Rebuild(Option<(String, RebuildReason)>),
    /// A live-born chart's seed, the engine's own, rebuilt afresh.
    Seed,
}

/// A workbook rebuild's resource refusal as the live error (FIX 10587).
fn resource(refusal: crate::resource::ResourceRefusal) -> LiveError {
    LiveError::Package(crate::retained_opc::Error::Resource(refusal))
}

/// The sheet the rebuilt data goes on in the chart's own workbook `book`,
/// as the chart part `first` references it ([`dataset::data_sheet`]): its
/// own data sheet, or a new one beside its sheets, or, `None`, none (the
/// rebuild is afresh). A resource refusal is the live error (FIX 10587),
/// never afresh.
fn rebuilt_sheet(
    package: &Package,
    book: &str,
    first: &crate::ooxml::XmlTree,
    mode: &Mode,
) -> Result<Option<String>, LiveError> {
    if !matches!(mode, Mode::Rebuild(Some(_))) {
        return Ok(None);
    }
    match package.part(book) {
        Ok(Some(source)) => {
            dataset::data_sheet(&source, first, package.limits(), package.resources())
                .map_err(resource)
        }
        Ok(None) => Ok(None),
        Err(error) => {
            if error.resource().is_some() {
                return Err(error.into());
            }
            Ok(None)
        }
    }
}

/// [`chart`]'s rewrite: into the chart's own workbook as `in_place` edits
/// it, over the resolution that edit read, or, without an edit, into one
/// rebuilt from the live data.
fn rewrite(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
    bound: &SeriesBinding,
    done: &mut Vec<Conversion>,
    mode: Mode,
) -> Result<(Vec<String>, Vec<NodeId>), LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        source,
        plots: settings,
        view,
    } = payload
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let mut changed = vec![chart.to_owned()];
    let mut beside = None;
    let (edit, read, book, note) = match mode {
        Mode::Edit(edit, read) => {
            let book = Some(edit.part.clone());
            (Some(edit), read, book, None)
        }
        mode => {
            let (_, first) = xml::read(package, chart)?;
            let wanted = wanted(&first, *family, categories, series, &bound.series);
            let book = match own_workbook(package, chart, &first)? {
                Some(book) => {
                    beside = rebuilt_sheet(package, &book, &first, &mode)?;
                    Some(book)
                }
                None if *source == ChartSource::Literal => None,
                None => {
                    let dataset = workbook_dataset(&wanted);
                    let workbook =
                        chart_workbook(&dataset, SHEET, package.limits(), package.resources())?;
                    let (book, embedded) = convert::embed_workbook(package, chart, workbook)?;
                    done.extend(embedded);
                    Some(book)
                }
            };
            let read = layout::resolve(package, chart, payload, &bound.series, Some(wanted))?;
            let note = match mode {
                Mode::Rebuild(reason) => reason,
                _ => None,
            };
            (None, read, book, note)
        }
    };
    let sheet = beside.clone().unwrap_or_else(|| SHEET.to_owned());
    let dataset = workbook_dataset(&read.wanted);
    let Resolved {
        bytes,
        tree,
        wanted: Wanted { sets, data, .. },
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
    // Each target's place among the targets of its family: the settings
    // it takes are that plot's ([`ChartPlot`]).
    let nths: Vec<u32> = targets
        .iter()
        .enumerate()
        .map(|(at, target)| {
            let count = targets[..at]
                .iter()
                .filter(|other| other.kind == target.kind)
                .count();
            u32::try_from(count).unwrap_or(u32::MAX)
        })
        .collect();
    let PlotAxes {
        held: held_axes,
        ids: ids_of,
        kept: held_ids,
        retyped,
        mid_cat,
        new: new_axes,
    } = plot_axes(&tree, area, (&plots, &targets), (&nths, settings), &writer);
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
    // Each target's series in the order it writes them: a stock plot's in
    // its price order, a placeholder (`None`) in each price none of its
    // series draws, so it keeps three or four series and each price its
    // place (FIX 9374).
    let plans: Vec<Vec<Option<usize>>> = targets
        .iter()
        .enumerate()
        .map(|(at, target)| {
            let roles = settings
                .iter()
                .find(|plot| target.kind == ChartKind::Stock && plot.is(target.kind, nths[at]))
                .and_then(|plot| plot.stock);
            let Some(roles) = roles else {
                return assigned[at].iter().copied().map(Some).collect();
            };
            let mut used = BTreeSet::new();
            let mut plan: Vec<Option<usize>> = Vec::with_capacity(assigned[at].len().max(4));
            for (_, id) in roles.slots() {
                let index = id.and_then(|id| {
                    assigned[at]
                        .iter()
                        .copied()
                        .find(|index| series[*index].id == Some(id) && !used.contains(index))
                });
                used.extend(index);
                plan.push(index);
            }
            plan.extend(
                assigned[at]
                    .iter()
                    .copied()
                    .filter(|index| !used.contains(index))
                    .map(Some),
            );
            plan
        })
        .collect();
    // Where a plan pads or reorders a plot, every series takes its place
    // in the written order as its `c:order`.
    let renumber = plans
        .iter()
        .zip(&assigned)
        .any(|(plan, assigned)| !plan.iter().copied().eq(assigned.iter().copied().map(Some)));
    let keep_order = keep_order && !renumber;
    let mut written_at: u32 = 0;
    let mut placeholders: Vec<u32> = Vec::new();
    let mut plot_xml: Vec<Vec<u8>> = Vec::with_capacity(targets.len());
    let mut emitted: Vec<usize> = Vec::with_capacity(seats.len());
    for (at_target, target) in targets.iter().enumerate() {
        let kind = target.kind;
        let kept = target.held.filter(|&at| plots[at].0 == kind);
        // How the plot lays its series out: the label positions its series
        // keep follow it (FIX 10297).
        let grouping = families::grouping(
            &tree,
            target.held.map(|at| plots[at].1),
            kind,
            settings,
            nths[at_target],
        );
        // A stock plot's close is drawn as a dot.
        let close = settings
            .iter()
            .find(|plot| plot.is(kind, nths[at_target]))
            .and_then(|plot| plot.stock)
            .and_then(|roles| roles.close);
        let mut sers = Vec::new();
        for &entry in &plans[at_target] {
            let place_at = written_at;
            written_at = written_at.saturating_add(1);
            let Some(index) = entry else {
                let minted = next_idx;
                next_idx = next_idx.saturating_add(1);
                sers.extend(special::placeholder(&tree, &writer, (minted, place_at)));
                placeholders.push(place_at);
                continue;
            };
            emitted.push(index);
            let seat = seats[index];
            let place = if renumber {
                place_at
            } else {
                u32::try_from(index).unwrap_or(u32::MAX)
            };
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
                        Refs::rebuilt(line, &sets, &sheet)
                    } else {
                        Refs::default()
                    };
                    &rebuilt
                }
            };
            let scatter = kind.draws_x();
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
            // Each category series writes the set it draws, flat or
            // multi-level, its own reference to it.
            let set = line.set.and_then(|set| sets.get(set));
            // Text x values are written as text (FIX 9277).
            let cat_xml = match (&line.x, scatter, set) {
                (Some(x), true, _) => writer.slot(
                    cat_name,
                    !line.x_text,
                    refs.first.as_deref(),
                    x,
                    &format_code(&bytes, &tree, cat_slot),
                ),
                (None, false, Some(set)) if set.multi() => {
                    writer.levels(cat_name, refs.first.as_deref(), &set.levels)
                }
                (None, false, Some(set)) => writer.slot(
                    cat_name,
                    set.numeric,
                    refs.first.as_deref(),
                    set.leaf(),
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
            // A bubble series' sizes, as its values are written; and its 3D
            // bubbles, as the model sets them.
            let bubble = kind == ChartKind::Bubble;
            let size_xml = match line.size.as_ref().filter(|_| bubble) {
                Some(size) => writer.slot(
                    "bubbleSize",
                    true,
                    refs.size.as_deref(),
                    size,
                    &format_code(
                        &bytes,
                        &tree,
                        seat.template
                            .and_then(|ser| xml::child(&tree, ser, C, "bubbleSize")),
                    ),
                ),
                None => String::new(),
            };
            let bubble_3d = series[index].bubble_3d.filter(|_| bubble);
            // A survivor's point formatting and labels follow its category
            // points by identity; without that evidence, its points by place.
            let points = Points {
                count: line.values.len(),
                remap: remap(bound, series[index].id, set),
            };
            // A survivor is written over its own series' bytes, in the plot
            // that held it or moved to another (FIX 8594); a new series is
            // formatted after its template.
            let own_plot = seat.held.and_then(|ser| tree.nodes[ser].parent);
            let in_kept = kept.is_some_and(|at| own_plot == Some(plots[at].1));
            let from = own_plot
                .and_then(|plot| held::plot_family(&tree.nodes[plot].name))
                .unwrap_or(kind);
            let was = families::grouping(&tree, own_plot, from, &[], 0);
            let is_close = close.is_some() && close == series[index].id;
            let stock = (kind == ChartKind::Stock && from != ChartKind::Stock)
                .then(|| special::stock_style(&tree, &writer, is_close));
            let mut dropped = Vec::new();
            sers.extend(match seat.held {
                Some(ser) => retained(
                    &bytes,
                    &tree,
                    ser,
                    (idx, order),
                    &writer,
                    ((from, was), (kind, grouping), !in_kept),
                    &Slots {
                        tx: &tx,
                        cat: &cat_xml,
                        val: &val_xml,
                        size: &size_xml,
                        bubble_3d,
                        stock,
                    },
                    &points,
                    &mut dropped,
                )?,
                None if kind == ChartKind::Stock => special::stock_series(
                    &tree,
                    &writer,
                    (idx, order),
                    is_close,
                    [&tx, &cat_xml, &val_xml],
                ),
                None => {
                    let tail = match bubble_3d {
                        Some(on) => format!(
                            r#"{size_xml}<{} val="{}"/>"#,
                            writer.el("bubble3D"),
                            bit(on)
                        ),
                        None => size_xml,
                    };
                    series::fresh(
                        &bytes,
                        &tree,
                        seat.template,
                        (kind, grouping),
                        &writer,
                        (idx, order),
                        [&tx, &cat_xml, &val_xml, &tail],
                    )
                }
            });
            if !dropped.is_empty() {
                done.push(Conversion::SeriesSettingsDropped {
                    series: series[index].name.clone(),
                    family: kind,
                    settings: dropped,
                });
            }
        }
        let place = (kind, nths[at_target]);
        let ids = &ids_of[at_target];
        // The category points the plot's first series draws, for an of-pie
        // plot's custom split.
        let split_points = assigned[at_target]
            .first()
            .and_then(|&index| data[index].set)
            .and_then(|set| sets.get(set))
            .map_or(&[][..], |set| set.ids.as_slice());
        let mut dropped = Vec::new();
        plot_xml.push(match kept {
            Some(at) => kept_plot(
                &bytes,
                &tree,
                plots[at].1,
                place,
                &sers,
                settings,
                (held_ids[at_target] != *ids).then_some(ids.as_slice()),
                &writer,
                split_points,
                &mut dropped,
            )?,
            None => fresh_plot(
                place,
                &writer,
                &sers,
                ids,
                settings,
                &Context {
                    bytes: &bytes,
                    tree: &tree,
                    from: target.held.map(|at| plots[at].1),
                    points: split_points,
                },
                &mut dropped,
            )?,
        });
        if !dropped.is_empty() {
            done.push(Conversion::PlotSettingsDropped {
                family: kind,
                settings: dropped,
            });
        }
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
            Some(&value) => axes_xml.extend(retyped_axis(&bytes, &tree, at, value, &writer)?),
            None if mid_cat.contains(&id) => {
                axes_xml.extend(mid_cat_axis(&bytes, &tree, at, &writer)?);
            }
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
    let mut splices = vec![(tree.nodes[area].span.clone(), out)];
    splices.extend(families::view(&bytes, &tree, view.as_ref(), &writer)?);
    splices.extend(special::legend_entries(
        &bytes,
        &tree,
        &writer,
        &placeholders,
    ));
    let next = xml::splice(&bytes, splices)?;
    package.replace_xml_part(chart, next)?;
    if let Some(book) = &book {
        let (workbook, notes) = match edit {
            Some(edit) => (edit.bytes, edit.notes),
            None => {
                let limits = package.limits();
                let resources = package.resources().clone();
                // The chart's own workbook keeps every other sheet, name and
                // table; where its editor refuses, the rebuild is afresh. A
                // resource refusal is the live error (FIX 10587), never afresh.
                let kept = match beside.as_deref() {
                    Some(name) => match package.part(book) {
                        Ok(Some(source)) => {
                            dataset::beside(&source, &dataset, name, limits, &resources)
                                .map_err(resource)?
                        }
                        Ok(None) => None,
                        Err(error) => {
                            if error.resource().is_some() {
                                return Err(error.into());
                            }
                            None
                        }
                    },
                    None => None,
                };
                if kept.is_none() {
                    beside = None;
                }
                let workbook = match kept {
                    Some(workbook) => workbook,
                    None => chart_workbook(&dataset, &sheet, limits, &resources)?,
                };
                (Some(workbook), Vec::new())
            }
        };
        if let Some(workbook) = workbook {
            package.replace_nested_package(book, workbook)?;
            changed.push(book.clone());
        }
        let read = chart_data(package, chart)?;
        let agree = read
            .series
            .iter()
            .flat_map(|line| {
                [
                    &line.name,
                    &line.categories,
                    &line.values,
                    &line.bubble_size,
                ]
            })
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
    // The part reads back as the live series in the order it holds them,
    // and as the settings of each plot it wrote and its 3D view (FIX 9274).
    let places: Vec<(ChartKind, u32)> = targets
        .iter()
        .zip(&nths)
        .map(|(target, &nth)| (target.kind, nth))
        .collect();
    let written = NodePayload::Chart {
        family: *family,
        categories: categories.clone(),
        series: emitted.iter().map(|&index| series[index].clone()).collect(),
        source: *source,
        plots: settings
            .iter()
            .filter(|plot| places.contains(&(plot.family, plot.nth)))
            .cloned()
            .collect(),
        view: *view,
    };
    let read = held::chart(package, chart)?.ok_or(LiveError::Invalid(READ_BACK))?;
    if !same_data(&read, &written) || !same_settings(&read, &written) {
        return Err(LiveError::Invalid(READ_BACK));
    }
    // Its stock prices and custom splits read back by identity, through the
    // binding this rewrite gives the part.
    if settings
        .iter()
        .any(|plot| plot.stock.is_some() || plot.custom_split.is_some())
    {
        let named: Vec<&ChartSeries> = emitted
            .iter()
            .map(|&index| &series[index])
            .filter(|line| line.id.is_some())
            .collect();
        let rebound = SeriesBinding {
            series: named.iter().filter_map(|line| line.id).collect(),
            categories: named
                .iter()
                .map(|line| {
                    if draws_categories(*family, line) {
                        effective_categories(categories, line).ids()
                    } else {
                        Vec::new()
                    }
                })
                .collect(),
        };
        let (_, tree) = xml::read(package, chart)?;
        if !held::same_named(&tree, &rebound, settings) {
            return Err(LiveError::Invalid(READ_BACK));
        }
    }
    if let Some((part, reason)) = note {
        done.push(Conversion::WorkbookRebuilt {
            part,
            reason,
            sheet: beside,
        });
    }
    let order = emitted
        .iter()
        .filter_map(|&index| series[index].id)
        .collect();
    Ok((changed, order))
}
