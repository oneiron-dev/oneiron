//! Step 4: the concurrent cases. The review-flow cases merge each pair of
//! forks in both landing orders (fork, preflight, land): a case that needs a
//! conflict must surface it in both orders; any other must land in both,
//! leave no dangling reference and export, and its other checks (the review
//! names the restyled slide, distinct allocated ids, a remapped or refused
//! build) hold in each order. That is fork replay, the merge a review lands
//! in landing order, so the two orders' heads are compared as landing-order
//! evidence, never as convergence ([`evidence`], FIX 8591). Convergence is
//! the engine's: two Loro peers of one body merged in both import orders
//! ([`peers`], FIX 3773). Each order's export is kept as a candidate.

mod evidence;
mod peers;

use super::checks;
use super::edits::{self, Anchor, Deck, Ids, Refused, add, apply_all, body, frame, shifted, stamp};
use super::record::{
    CONCURRENCY, DOCUMENT, Emit, FIXED_POINT, Lane, ORACLE, OfficeCheck, Res, Run, failed, text,
};
use super::spec::MergeCase;
use super::variants;
use crate::deck::{DeckView, TextRange};
use crate::edit::{EditRefusal, NoAssets, Preset};
use crate::live::deck_export::{ExportOutcome, ExportProfile, StepOutcome, project};
use crate::live::{
    ApproveScope, Conflict, DeckFork, DeckOp, Landing, LiveDeck, LiveError, NodeId, NodeKind,
    PreflightReport, land, preflight,
};
use crate::resource::Resources;
use crate::retained_opc::{Limits, Package};
use evidence::{Evidence, export_over, landed, surfaced};
use std::collections::BTreeSet;

/// Who lands both forks: never either proposer.
const SETTLER: &str = "deck-oracle-settler";
const ORDERS: [&str; 2] = ["a then b", "b then a"];

/// The base every case forks from: the baseline with a group of two, a free
/// shape and a second slide, exported and rebound to that export.
struct Prepared {
    head: LiveDeck,
    package: Package,
    /// The base's exported bytes: the deck its cases' candidates come from.
    origin: Vec<u8>,
    slide: NodeId,
    slide2: NodeId,
    group: NodeId,
    child: NodeId,
    free: NodeId,
    defects: Vec<String>,
}

/// One landing order's result: the head after both landings (or after the
/// first, when the second was held), and the second fork's preflight.
struct Merged {
    deck: LiveDeck,
    second: PreflightReport,
    landed: bool,
}

pub(super) fn cases(
    run: &mut Run,
    base: &Deck,
    anchor: &Anchor,
    animated: Option<&Deck>,
    cases: &[MergeCase],
) -> Res<()> {
    let base_id = format!("{}.merge.base", base.id);
    let prepared = match run.case(&base_id, |run| Ok(prepare(run, base, anchor)))? {
        Ok(prepared) => prepared,
        Err(why) => {
            for case in cases {
                let id = format!("{}.merge.{}", base.id, case.name());
                run.case(&id, |run| {
                    run.record(CONCURRENCY, &id, failed(format!("the merge base: {why}")));
                    Ok(())
                })?;
            }
            return Ok(());
        }
    };
    for case in cases {
        let id = format!("{}.merge.{}", base.id, case.name());
        run.case(&id, |run| merged_case(run, *case, &prepared, animated, &id))?;
    }
    Ok(())
}

/// One merge case over the prepared base, journaled as one case with the
/// evidence it captured, on a pass or a failure alike.
fn merged_case(
    run: &mut Run,
    case: MergeCase,
    prepared: &Prepared,
    animated: Option<&Deck>,
    id: &str,
) -> Res<()> {
    let mut evidence = Evidence::default();
    let passed = |result: Res<()>| result.map(|()| StepOutcome::Passed);
    let outcome = match case {
        MergeCase::LoroPeers => peers::loro_peers(run.peers, prepared, &mut evidence),
        MergeCase::TextAnimationRange => match animated {
            Some(animated) => passed(text_animation_range(animated, run.limits, &mut evidence)),
            None => Err("the animated variant was not built".to_owned()),
        },
        _ => passed(merge_case(case, prepared, run.limits, &mut evidence)),
    };
    let (baseline, origin) = match (case, animated) {
        (MergeCase::TextAnimationRange, Some(animated)) => (&animated.defects, &animated.bytes),
        _ => (&prepared.defects, &prepared.origin),
    };
    run.record(CONCURRENCY, id, outcome.unwrap_or_else(failed));
    evidence.flush(run, id, baseline, origin)
}

fn prepare(run: &mut Run, base: &Deck, anchor: &Anchor) -> Res<Prepared> {
    let mut ids = Ids::above(&base.deck);
    let s = anchor.slide;
    let (ops, nodes) = base_ops(&mut ids, s);
    let mut head = base.deck.clone();
    apply_all(&mut head, &ops).map_err(|error| format!("it does not apply: {error}"))?;
    let outcome = project(
        &head,
        &base.package,
        DOCUMENT,
        &ExportProfile::default(),
        &NoAssets,
    )
    .map_err(|error| format!("it does not export: {error}"))?;
    let id = format!("{}.merge.base", base.id);
    run.record(
        FIXED_POINT,
        &id,
        checks::fixed_point(&head, &base.package, &outcome, run.limits),
    );
    head.rebind(&outcome)
        .map_err(|error| format!("it does not rebind: {error}"))?;
    let package =
        Package::open(&outcome.bytes, run.limits, &Resources::measuring()).map_err(text)?;
    let defects = checks::defects(&outcome.bytes, run.limits);
    let origin = outcome.bytes.clone();
    let text_checks = [(1, "Free shape"), (1, "Group child"), (2, "Second slide")]
        .into_iter()
        .map(|(slide, contains)| OfficeCheck::Text {
            slide,
            contains: contains.to_owned(),
        });
    run.candidate(Emit {
        id: &id,
        bytes: &outcome.bytes,
        steps: &[ORACLE],
        lane: Lane::Core,
        checks: [
            OfficeCheck::Slides { count: 2 },
            OfficeCheck::Pages { count: 2 },
        ]
        .into_iter()
        .chain(text_checks)
        .collect(),
        baseline: &base.defects,
        origin: &base.bytes,
    })?;
    Ok(Prepared {
        head,
        package,
        origin,
        slide: s,
        slide2: nodes.slide2,
        group: nodes.group,
        child: nodes.child,
        free: nodes.free,
        defects,
    })
}

/// The merge base's own nodes.
struct BaseNodes {
    group: NodeId,
    child: NodeId,
    free: NodeId,
    slide2: NodeId,
}

/// The operations that build the merge base on slide `s`: a group of two
/// (one with text), a free text shape, and a second slide with a text shape.
fn base_ops(ids: &mut Ids, s: NodeId) -> (Vec<DeckOp>, BaseNodes) {
    let (group, child, second_child, free, slide2, second) = (
        ids.mint(),
        ids.mint(),
        ids.mint(),
        ids.mint(),
        ids.mint(),
        ids.mint(),
    );
    let ops = vec![
        add(group, s, NodeKind::Group, "Merge group", None, None),
        add(
            child,
            group,
            NodeKind::Shape,
            "Group child",
            Some(Preset::Rect),
            None,
        ),
        DeckOp::SetGeometry {
            node: child,
            geometry: frame(914_400, 2_743_200, 1_828_800, 685_800),
        },
        DeckOp::SetText {
            node: child,
            body: body(ids, "Group child"),
        },
        add(
            second_child,
            group,
            NodeKind::Shape,
            "Group second",
            Some(Preset::Ellipse),
            None,
        ),
        DeckOp::SetGeometry {
            node: second_child,
            geometry: frame(3_200_400, 2_743_200, 914_400, 685_800),
        },
        add(
            free,
            s,
            NodeKind::Shape,
            "Free shape",
            Some(Preset::Rect),
            None,
        ),
        DeckOp::SetGeometry {
            node: free,
            geometry: frame(914_400, 4_572_000, 2_743_200, 685_800),
        },
        DeckOp::SetText {
            node: free,
            body: body(ids, "Free shape"),
        },
        DeckOp::AddSlide { id: Some(slide2) },
        add(
            second,
            slide2,
            NodeKind::Shape,
            "Second slide shape",
            Some(Preset::Rect),
            None,
        ),
        DeckOp::SetGeometry {
            node: second,
            geometry: frame(914_400, 914_400, 4_572_000, 914_400),
        },
        DeckOp::SetText {
            node: second,
            body: body(ids, "Second slide"),
        },
    ];
    (
        ops,
        BaseNodes {
            group,
            child,
            free,
            slide2,
        },
    )
}

fn fork(head: &LiveDeck, side: &str, ops: Vec<DeckOp>) -> DeckFork {
    let proposer = format!("peer-{side}");
    let mut fork = head.fork_at(&format!("merge-{side}"), &proposer, None);
    for (at, op) in ops.into_iter().enumerate() {
        fork.record(stamp(&proposer, at, op));
    }
    fork
}

fn land_one(deck: &mut LiveDeck, fork: &DeckFork, report: &PreflightReport) -> Res<()> {
    land(
        deck,
        fork,
        report,
        SETTLER,
        ApproveScope::OneItem(fork.proposal.clone()),
        Landing::Merge,
        true,
    )
    .map(|_| ())
    .map_err(text)
}

/// Land `first` on the head, then preflight `second` and land it when it
/// holds no conflict.
fn merge(head: &LiveDeck, first: &DeckFork, second: &DeckFork) -> Res<Merged> {
    let mut deck = head.clone();
    let opening = preflight(&deck, first).map_err(text)?;
    if !opening.ok {
        return Err(format!(
            "{} does not land on its own base: {:?} {:?}",
            first.proposal, opening.diff.conflicts, opening.replay_refusals
        ));
    }
    land_one(&mut deck, first, &opening)?;
    let report = preflight(&deck, second).map_err(text)?;
    let landed = report.ok;
    if landed {
        land_one(&mut deck, second, &report)?;
    }
    Ok(Merged {
        deck,
        second: report,
        landed,
    })
}

fn both(head: &LiveDeck, a: Vec<DeckOp>, b: Vec<DeckOp>) -> Res<[Merged; 2]> {
    let (a, b) = (fork(head, "a", a), fork(head, "b", b));
    Ok([merge(head, &a, &b)?, merge(head, &b, &a)?])
}

fn merge_case(case: MergeCase, p: &Prepared, limits: Limits, evidence: &mut Evidence) -> Res<()> {
    match case {
        MergeCase::BothMove => {
            let orders = both(
                &p.head,
                vec![move_to(p.free, p.slide, 0)],
                vec![move_to(p.free, p.slide2, 0)],
            )?;
            surfaced(
                &orders,
                "both-moved",
                |c| matches!(c, Conflict::BothMoved { node } if *node == p.free),
            )
        }
        MergeCase::BothMoveSame => {
            let orders = both(
                &p.head,
                vec![move_to(p.free, p.slide, 0)],
                vec![move_to(p.free, p.slide, 0)],
            )?;
            landed(&orders)?;
            evidence.compare(&orders);
            evidence.export_both(&orders, &p.package)?;
            evidence.compare_exports();
            Ok(())
        }
        MergeCase::DeleteGroupEditChild => {
            let mut ids = Ids::above(&p.head);
            let orders = both(
                &p.head,
                vec![DeckOp::RemoveNode { node: p.group }],
                vec![DeckOp::SetText {
                    node: p.child,
                    body: body(&mut ids, "Edited child"),
                }],
            )?;
            surfaced(
                &orders,
                "deleted-versus-edited",
                |c| matches!(c, Conflict::DeletedVsEdited { node, .. } if *node == p.child || *node == p.group),
            )
        }
        MergeCase::ReparentGeometry => {
            let orders = both(
                &p.head,
                vec![move_to(p.child, p.slide, 0)],
                vec![DeckOp::SetGeometry {
                    node: p.child,
                    geometry: shifted(p.head.nodes[&p.child].geometry),
                }],
            )?;
            surfaced(
                &orders,
                "geometry-versus-reparent",
                |c| matches!(c, Conflict::GeometryVsReparent { node } if *node == p.child),
            )
        }
        MergeCase::ThemeInheritedStyle => theme_inherited_style(p, limits, evidence),
        MergeCase::BothReplaceOpaque => {
            let (theme, old) = theme_of(p)?;
            let replace = |face: &str| -> Res<DeckOp> {
                let bytes = variants::retheme(&p.package, &theme, face)?;
                Ok(DeckOp::ReplaceOpaque {
                    part: theme.clone(),
                    expected: old,
                    replacement: *blake3::hash(&bytes).as_bytes(),
                })
            };
            let orders = both(
                &p.head,
                vec![replace("Georgia")?],
                vec![replace("Cambria")?],
            )?;
            surfaced(
                &orders,
                "both-replaced-opaque",
                |c| matches!(c, Conflict::BothReplacedOpaque { part } if *part == theme),
            )
        }
        MergeCase::BothAddShape => both_add_shape(p, evidence),
        MergeCase::TextAnimationRange | MergeCase::LoroPeers => {
            Err("routed to its own case".to_owned())
        }
    }
}

fn move_to(node: NodeId, new_parent: NodeId, index: usize) -> DeckOp {
    DeckOp::MoveNode {
        node,
        new_parent,
        index,
    }
}

/// The first slide's theme part and the hash the head holds for it.
fn theme_of(p: &Prepared) -> Res<(String, [u8; 32])> {
    let view = DeckView::read(&p.package).map_err(text)?;
    let theme = view
        .slides
        .first()
        .and_then(|slide| slide.theme.clone())
        .ok_or("the first slide resolves no theme")?;
    let old = *p
        .head
        .opaque_parts
        .get(&theme)
        .ok_or("the theme is not an opaque part of the head")?;
    Ok((theme, old))
}

/// Replace the theme on one side while the other sets a run to inherit the
/// theme's body font: both land, the review shows the restyled slide in
/// both orders, and the run's effective font follows the new theme.
fn theme_inherited_style(p: &Prepared, limits: Limits, evidence: &mut Evidence) -> Res<()> {
    let (theme, old) = theme_of(p)?;
    let new_theme = variants::retheme(&p.package, &theme, "Georgia")?;
    let paragraph = p
        .head
        .texts
        .get(&p.free)
        .and_then(|body| body.paragraphs.first())
        .ok_or("the free shape has no paragraph")?;
    let mut runs = paragraph.runs.clone();
    for run in &mut runs {
        run.latin = Some("+mn-lt".to_owned());
    }
    let restyle = vec![DeckOp::SetRunMarks {
        node: p.free,
        paragraph: paragraph.id,
        runs,
    }];
    let replace = vec![DeckOp::ReplaceOpaque {
        part: theme.clone(),
        expected: old,
        replacement: *blake3::hash(&new_theme).as_bytes(),
    }];
    let orders = both(&p.head, replace, restyle.clone())?;
    landed(&orders)?;
    evidence.compare(&orders);
    for (order, merged) in ORDERS.iter().zip(&orders) {
        if !merged.second.diff.affected_slides.contains(&p.slide) {
            return Err(format!(
                "{order}: the review does not show the restyled slide among {:?}",
                merged.second.diff.affected_slides
            ));
        }
    }
    let mut rethemed = p.package.clone();
    rethemed.replace_xml_part(&theme, new_theme).map_err(text)?;
    let merged = evidence.export_both(&orders, &rethemed)?;
    evidence.compare_exports();
    let mut alone = p.head.clone();
    apply_all(&mut alone, &restyle).map_err(text)?;
    let alone = export_over(&alone, &p.package, "the restyle alone")?;
    let bound = p.head.nodes[&p.free]
        .binding
        .as_ref()
        .ok_or("the free shape is not bound")?;
    let native = bound.native_id.ok_or("the free shape has no native id")?;
    let before = fonts(&alone.bytes, limits, &bound.slide_part, native)?;
    for (order, outcome) in ORDERS.iter().zip(&merged) {
        let after = fonts(&outcome.bytes, limits, &bound.slide_part, native)?;
        if before == after {
            return Err(format!(
                "{order}: the theme replacement changed no effective font of the restyled run ({after:?})"
            ));
        }
    }
    Ok(())
}

/// The resolved Latin font of each run of one shape.
fn fonts(bytes: &[u8], limits: Limits, part: &str, native: u32) -> Res<Vec<String>> {
    let package = Package::open(bytes, limits, &Resources::measuring()).map_err(text)?;
    let view = DeckView::read(&package).map_err(text)?;
    let shape = view
        .slides
        .iter()
        .filter(|slide| slide.part == part)
        .flat_map(|slide| &slide.shapes)
        .find(|shape| shape.id == Some(native))
        .ok_or("the restyled shape is missing")?;
    let read = shape
        .text
        .as_ref()
        .ok_or("the restyled shape has no text")?;
    Ok(read
        .paragraphs
        .iter()
        .flat_map(|paragraph| &paragraph.runs)
        .map(|run| format!("{:?}", run.latin.value))
        .collect())
}

/// Both sides create a shape on one slide: both land, and the merged export
/// allocates two distinct native ids above the slide's own, whatever ids
/// each side's own export gave.
fn both_add_shape(p: &Prepared, evidence: &mut Evidence) -> Res<()> {
    let mut ids = Ids::above(&p.head);
    let (na, nb) = (ids.mint(), ids.mint());
    let side = |node: NodeId, preset: Preset, y: i64, label: &str, ids: &mut Ids| {
        vec![
            add(node, p.slide, NodeKind::Shape, label, Some(preset), None),
            DeckOp::SetGeometry {
                node,
                geometry: frame(4_572_000, y, 1_828_800, 685_800),
            },
            DeckOp::SetText {
                node,
                body: body(ids, label),
            },
        ]
    };
    let a = side(na, Preset::Rect, 914_400, "Peer A shape", &mut ids);
    let b = side(nb, Preset::Ellipse, 1_828_800, "Peer B shape", &mut ids);
    let mut alone = Vec::new();
    for (node, ops) in [(na, &a), (nb, &b)] {
        let mut deck = p.head.clone();
        apply_all(&mut deck, ops).map_err(text)?;
        let outcome = export_over(&deck, &p.package, "one side alone")?;
        alone.push(
            outcome
                .bindings
                .get(&node)
                .and_then(|bound| bound.native_id),
        );
    }
    let orders = both(&p.head, a, b)?;
    landed(&orders)?;
    evidence.compare(&orders);
    let view = DeckView::read(&p.package).map_err(text)?;
    let slide_part = p.head.nodes[&p.slide]
        .binding
        .as_ref()
        .map(|bound| bound.slide_part.clone())
        .ok_or("the slide is not bound")?;
    let held: BTreeSet<u32> = view
        .slides
        .iter()
        .filter(|slide| slide.part == slide_part)
        .flat_map(|slide| slide.shapes.iter().filter_map(|shape| shape.id))
        .collect();
    let exports = evidence.export_both(&orders, &p.package)?;
    evidence.compare_exports();
    for (order, outcome) in ORDERS.iter().zip(&exports) {
        let id = |node: NodeId| {
            outcome
                .bindings
                .get(&node)
                .and_then(|bound| bound.native_id)
        };
        match (id(na), id(nb)) {
            (Some(x), Some(y)) if x != y && !held.contains(&x) && !held.contains(&y) => {}
            found => {
                return Err(format!(
                    "{order}: the merged export allocated {found:?} beside the slide's {held:?} (each side alone: {alone:?})"
                ));
            }
        }
    }
    Ok(())
}

/// The text edit that moves an animated paragraph, merged with a geometry
/// edit of the same shape: both land and converge, and the merged export
/// either refuses (the build would target other text) or remaps the build
/// onto the paragraph it named (ARCH-0077: "Remap within the tested subset
/// or refuse").
fn text_animation_range(animated: &Deck, limits: Limits, evidence: &mut Evidence) -> Res<()> {
    let anchor = edits::anchor(&animated.deck)?;
    let head = &animated.deck;
    let mut ids = Ids::above(head);
    let original = head
        .texts
        .get(&anchor.shape)
        .ok_or("the animated shape has no text")?;
    let held = original
        .paragraphs
        .first()
        .ok_or("the animated shape has no paragraph")?
        .id;
    let mut prepended = original.clone();
    prepended.paragraphs.insert(
        0,
        body(&mut ids, "Inserted before the build")
            .paragraphs
            .remove(0),
    );
    let orders = both(
        head,
        vec![DeckOp::SetText {
            node: anchor.shape,
            body: prepended,
        }],
        vec![DeckOp::SetGeometry {
            node: anchor.shape,
            geometry: shifted(head.nodes[&anchor.shape].geometry),
        }],
    )?;
    landed(&orders)?;
    evidence.compare(&orders);
    // Each order exports, refusing the moved build as canon allows or
    // remapping it onto the paragraph it named; both are kept.
    let mut failures = Vec::new();
    for (order, merged) in ORDERS.into_iter().zip(&orders) {
        let merged = &merged.deck;
        let at = merged
            .texts
            .get(&anchor.shape)
            .and_then(|body| {
                body.paragraphs
                    .iter()
                    .position(|paragraph| paragraph.id == held)
            })
            .ok_or("the built paragraph is gone from the merged text")?;
        match project(
            merged,
            &animated.package,
            DOCUMENT,
            &ExportProfile::default(),
            &NoAssets,
        ) {
            Err(error) if animation_refusal(&error) => {
                evidence.keep(order, Err(format!("refused as canon allows: {error}")));
            }
            Err(error) => {
                let why = Refused::Export(error).why();
                failures.push(format!("{order}: {why}"));
                evidence.keep(order, Err(why));
            }
            Ok(outcome) => {
                let index = u32::try_from(at).map_err(text)?;
                let ranges = built_ranges(&outcome, limits, &anchor)?;
                if ranges.is_empty() || ranges.iter().any(|range| *range != (index, index)) {
                    failures.push(format!(
                        "{order}: the build targets paragraphs {ranges:?}; its paragraph is now {index}"
                    ));
                }
                evidence.keep(order, Ok(outcome.bytes));
            }
        }
    }
    evidence.compare_exports();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// The refusals canon accepts for an edit that moves animated text.
pub(super) fn animation_refusal(error: &LiveError) -> bool {
    matches!(
        error,
        LiveError::Edit(
            EditRefusal::AnimatedTextStructureChanged
                | EditRefusal::AnimationDependencyUnsupported(_)
        )
    )
}

/// The paragraph ranges the exported slide's animations target on the
/// anchored shape.
pub(super) fn built_ranges(
    outcome: &ExportOutcome,
    limits: Limits,
    anchor: &Anchor,
) -> Res<Vec<(u32, u32)>> {
    let bound = outcome
        .bindings
        .get(&anchor.shape)
        .ok_or("the animated shape has no binding in the export")?;
    let native = bound
        .native_id
        .ok_or("the animated shape has no native id")?;
    let package = Package::open(&outcome.bytes, limits, &Resources::measuring()).map_err(text)?;
    let view = DeckView::read(&package).map_err(text)?;
    let slide = view
        .slides
        .iter()
        .find(|slide| slide.part == bound.slide_part)
        .ok_or("the animated slide is missing")?;
    Ok(slide
        .animation
        .targets_of(native)
        .filter_map(|target| match target.text {
            Some(TextRange::Paragraphs { start, end }) => Some((start, end)),
            _ => None,
        })
        .collect())
}
